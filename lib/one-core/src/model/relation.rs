use std::collections::{HashMap, HashSet};
use std::fmt::{Debug, Display};
use std::hash::Hash;
use std::ops::{Deref, DerefMut};
use std::sync::Arc;

use tokio::sync::{OnceCell, RwLock, RwLockReadGuard, RwLockWriteGuard};

use crate::error::{ContextWithErrorCode, ErrorCode, ErrorCodeMixin, NestedError};
use crate::repository::error::DataLayerError;

pub trait Model {
    type Id: Clone + Debug + Display;
    fn id(&self) -> &Self::Id;
}

// Related model
#[async_trait::async_trait]
pub trait AsyncModelLoader<M: Model>: Send + Sync {
    async fn load(&self, id: &M::Id) -> Result<M, DataLayerError>;
}

#[derive(Clone, Debug)]
pub struct Related<M: Model> {
    id: M::Id,
    data: Arc<RwLock<AsyncModelStore<M>>>,
}

impl<M: Model> Related<M> {
    pub fn new(id: M::Id, loader: impl AsyncModelLoader<M> + 'static) -> Self {
        Self {
            id,
            data: Arc::new(RwLock::new(AsyncModelStore::ToBeLoaded(Box::new(loader)))),
        }
    }

    pub fn id_ref(&self) -> &M::Id {
        &self.id
    }
}

impl<M: Model> Related<M>
where
    M::Id: Copy,
{
    pub fn id(&self) -> M::Id {
        self.id
    }
}

impl<M: Model> Related<M> {
    pub async fn as_ref(&self) -> Result<RoLoadedRelated<'_, M>, NestedError> {
        if let Some(loaded) = self.load_for_read_only().await? {
            return Ok(loaded);
        };
        let guard = self.data.read().await;
        Ok(RoLoadedRelated { guard })
    }

    pub async fn as_mut(&mut self) -> Result<RwLoadedRelated<'_, M>, NestedError> {
        self.load().await
    }

    async fn load_for_read_only(&self) -> Result<Option<RoLoadedRelated<'_, M>>, NestedError> {
        // IMPORTANT: Check with a read lock first whether the data is already loaded. If it is,
        // most likely there are other read locks being held currently, so that trying to acquire
        // a write lock directly would cause a deadlock.
        {
            let guard = self.data.read().await;
            if let AsyncModelStore::AlreadyLoaded(_) = *guard {
                return Ok(Some(RoLoadedRelated { guard }));
            }
        }
        self.load().await?;
        Ok(None)
    }

    async fn load(&self) -> Result<RwLoadedRelated<'_, M>, NestedError> {
        let mut guard = self.data.write().await;
        if let AsyncModelStore::ToBeLoaded(loader) = &*guard {
            let data = loader
                .load(&self.id)
                .await
                .error_while(format!("loading related entity {}", self.id))?;
            *guard = AsyncModelStore::AlreadyLoaded(data);
        }
        Ok(RwLoadedRelated { guard })
    }
}

#[derive(Debug)]
pub struct RoLoadedRelated<'a, M: Model> {
    guard: RwLockReadGuard<'a, AsyncModelStore<M>>,
}

impl<M: Model> AsRef<M> for RoLoadedRelated<'_, M> {
    fn as_ref(&self) -> &M {
        match &*self.guard {
            AsyncModelStore::AlreadyLoaded(data) => data,
            AsyncModelStore::ToBeLoaded(_) => unreachable!(
                "Invariant violated: load not called before constructing loaded related ref."
            ),
        }
    }
}

impl<M: Model> Deref for RoLoadedRelated<'_, M> {
    type Target = M;

    fn deref(&self) -> &Self::Target {
        self.as_ref()
    }
}

#[derive(Debug)]
pub struct RwLoadedRelated<'a, M: Model> {
    guard: RwLockWriteGuard<'a, AsyncModelStore<M>>,
}

impl<M: Model> AsRef<M> for RwLoadedRelated<'_, M> {
    fn as_ref(&self) -> &M {
        match &*self.guard {
            AsyncModelStore::AlreadyLoaded(data) => data,
            AsyncModelStore::ToBeLoaded(_) => unreachable!(
                "Invariant violated: load not called before constructing loaded related ref."
            ),
        }
    }
}

impl<M: Model> Deref for RwLoadedRelated<'_, M> {
    type Target = M;

    fn deref(&self) -> &Self::Target {
        self.as_ref()
    }
}

impl<M: Model> DerefMut for RwLoadedRelated<'_, M> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.as_mut()
    }
}

impl<M: Model> AsMut<M> for RwLoadedRelated<'_, M> {
    fn as_mut(&mut self) -> &mut M {
        match &mut *self.guard {
            AsyncModelStore::AlreadyLoaded(data) => data,
            AsyncModelStore::ToBeLoaded(_) => unreachable!(
                "Invariant violated: load not called before constructing loaded related ref."
            ),
        }
    }
}

impl<M: Model> From<M> for Related<M> {
    fn from(model: M) -> Self {
        Self {
            id: model.id().to_owned(),
            data: Arc::new(RwLock::new(AsyncModelStore::AlreadyLoaded(model))),
        }
    }
}

#[cfg(any(test, feature = "mock"))]
impl<M: Model> PartialEq for Related<M>
where
    M::Id: PartialEq,
{
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

// Related models collection
#[async_trait::async_trait]
pub trait AsyncModelsLoader<M: Model>: Send + Sync {
    /// Loads collection of models specified by `ids`
    async fn load(&self, ids: &[M::Id]) -> Result<Vec<M>, DataLayerError>;
}

#[async_trait::async_trait]
pub trait AsyncVecLoader<T>: Send + Sync {
    /// Loads collection of relations
    async fn load(&self) -> Result<Vec<T>, DataLayerError>;
}

#[async_trait::async_trait]
pub trait AsyncBatchLoader<K, V>: Send + Sync {
    /// Loads map of relations
    async fn load(&self, ids: &[K]) -> Result<HashMap<K, V>, DataLayerError>;
}

#[async_trait::async_trait]
impl<M, L> AsyncBatchLoader<M::Id, M> for L
where
    M: Model + Send + Sync,
    M::Id: Eq + Hash + Send + Sync,
    L: AsyncModelsLoader<M>,
{
    async fn load(&self, ids: &[M::Id]) -> Result<HashMap<M::Id, M>, DataLayerError> {
        let models = AsyncModelsLoader::load(self, ids).await?;
        Ok(models
            .into_iter()
            .map(|model| (model.id().to_owned(), model))
            .collect())
    }
}

#[async_trait::async_trait]
pub trait OptionalRelatedExt<M: Model> {
    /// access id on the optional relation
    fn id_opt(&self) -> Option<M::Id>;
    /// access id reference on the optional relation
    fn id_opt_ref(&self) -> Option<&M::Id>;

    /// fetches the relation, fails if missing
    async fn as_required_ref(&self) -> Result<RoLoadedRelated<'_, M>, NestedError>;
    /// fetches the relation for modification, fails if missing
    async fn as_required_mut(&mut self) -> Result<RwLoadedRelated<'_, M>, NestedError>;
}

#[derive(Debug, thiserror::Error)]
pub enum OptionalRelatedExtError {
    #[error("Missing relation: {0}")]
    MissingRelation(&'static str),
}

impl ErrorCodeMixin for OptionalRelatedExtError {
    fn error_code(&self) -> ErrorCode {
        ErrorCode::BR_0047
    }
}

#[async_trait::async_trait]
impl<M: Model + Send + Sync> OptionalRelatedExt<M> for Option<Related<M>>
where
    M::Id: Copy + Send + Sync,
{
    fn id_opt(&self) -> Option<M::Id> {
        self.as_ref().map(|related| related.id())
    }

    fn id_opt_ref(&self) -> Option<&M::Id> {
        self.as_ref().map(|related| related.id_ref())
    }

    async fn as_required_ref(&self) -> Result<RoLoadedRelated<'_, M>, NestedError> {
        self.as_ref()
            .ok_or_else(|| OptionalRelatedExtError::MissingRelation(std::any::type_name::<M>()))?
            .as_ref()
            .await
    }

    async fn as_required_mut(&mut self) -> Result<RwLoadedRelated<'_, M>, NestedError> {
        self.as_mut()
            .ok_or_else(|| OptionalRelatedExtError::MissingRelation(std::any::type_name::<M>()))?
            .as_mut()
            .await
    }
}

#[derive(Clone, Debug)]
pub struct RelatedVec<T> {
    data: Arc<RwLock<AsyncVecStore<T>>>,
}

impl<T> RelatedVec<T> {
    pub fn new(loader: impl AsyncVecLoader<T> + 'static) -> Self {
        Self {
            data: Arc::new(RwLock::new(AsyncVecStore::ToBeLoaded(Box::new(loader)))),
        }
    }

    pub async fn as_ref(&self) -> Result<RoLoadedRelatedVec<'_, T>, NestedError> {
        if let Some(loaded) = self.load_for_read_only().await? {
            return Ok(loaded);
        };
        let guard = self.data.read().await;
        Ok(RoLoadedRelatedVec { guard })
    }

    pub async fn as_mut(&mut self) -> Result<RwLoadedRelatedVec<'_, T>, NestedError> {
        self.load().await
    }

    async fn load_for_read_only(&self) -> Result<Option<RoLoadedRelatedVec<'_, T>>, NestedError> {
        // IMPORTANT: Check with a read lock first whether the data is already loaded. If it is,
        // most likely there are other read locks being held currently, so that trying to acquire
        // a write lock directly would cause a deadlock.
        {
            let guard = self.data.read().await;
            if let AsyncVecStore::AlreadyLoaded(_) = *guard {
                return Ok(Some(RoLoadedRelatedVec { guard }));
            }
        }
        self.load().await?;
        Ok(None)
    }

    async fn load(&self) -> Result<RwLoadedRelatedVec<'_, T>, NestedError> {
        let mut guard = self.data.write().await;
        if let AsyncVecStore::ToBeLoaded(loader) = &*guard {
            let data = loader
                .load()
                .await
                .error_while("loading related entities".to_string())?;
            *guard = AsyncVecStore::AlreadyLoaded(data);
        }
        Ok(RwLoadedRelatedVec { guard })
    }
}

#[derive(Debug)]
pub struct RoLoadedRelatedVec<'a, M> {
    guard: RwLockReadGuard<'a, AsyncVecStore<M>>,
}

impl<M> AsRef<Vec<M>> for RoLoadedRelatedVec<'_, M> {
    fn as_ref(&self) -> &Vec<M> {
        match &*self.guard {
            AsyncVecStore::AlreadyLoaded(data) => data,
            AsyncVecStore::ToBeLoaded(_) => unreachable!(
                "Invariant violated: load not called before constructing loaded related vec."
            ),
        }
    }
}

impl<M> Deref for RoLoadedRelatedVec<'_, M> {
    type Target = Vec<M>;

    fn deref(&self) -> &Self::Target {
        self.as_ref()
    }
}

impl<'a, M> IntoIterator for &'a RoLoadedRelatedVec<'_, M> {
    type Item = &'a M;
    type IntoIter = std::slice::Iter<'a, M>;

    fn into_iter(self) -> Self::IntoIter {
        self.as_ref().iter()
    }
}

#[derive(Debug)]
pub struct RwLoadedRelatedVec<'a, M> {
    guard: RwLockWriteGuard<'a, AsyncVecStore<M>>,
}

impl<M> AsRef<Vec<M>> for RwLoadedRelatedVec<'_, M> {
    fn as_ref(&self) -> &Vec<M> {
        match &*self.guard {
            AsyncVecStore::AlreadyLoaded(data) => data,
            AsyncVecStore::ToBeLoaded(_) => unreachable!(
                "Invariant violated: load not called before constructing loaded related vec."
            ),
        }
    }
}

impl<M> Deref for RwLoadedRelatedVec<'_, M> {
    type Target = Vec<M>;

    fn deref(&self) -> &Self::Target {
        self.as_ref()
    }
}

impl<M> DerefMut for RwLoadedRelatedVec<'_, M> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.as_mut()
    }
}

impl<M> AsMut<Vec<M>> for RwLoadedRelatedVec<'_, M> {
    fn as_mut(&mut self) -> &mut Vec<M> {
        match &mut *self.guard {
            AsyncVecStore::AlreadyLoaded(data) => data,
            AsyncVecStore::ToBeLoaded(_) => unreachable!(
                "Invariant violated: load not called before constructing loaded related vec."
            ),
        }
    }
}

impl<'a, M> IntoIterator for &'a mut RwLoadedRelatedVec<'_, M> {
    type Item = &'a mut M;
    type IntoIter = std::slice::IterMut<'a, M>;

    fn into_iter(self) -> Self::IntoIter {
        self.as_mut().iter_mut()
    }
}

impl<T> From<Vec<T>> for RelatedVec<T> {
    fn from(models: Vec<T>) -> Self {
        Self {
            data: Arc::new(RwLock::new(AsyncVecStore::AlreadyLoaded(models))),
        }
    }
}

impl<M: Model + 'static> RelatedVec<M>
where
    M::Id: Send + Sync,
{
    pub fn from_ids(
        ids: impl Into<Vec<M::Id>>,
        loader: impl AsyncModelsLoader<M> + 'static,
    ) -> Self {
        Self::new(ModelsLoaderWrapper {
            ids: ids.into(),
            loader: Box::new(loader),
        })
    }
}

impl<T> Default for RelatedVec<T> {
    fn default() -> Self {
        Self::from(Vec::default())
    }
}

#[cfg(any(test, feature = "mock"))]
impl<T> PartialEq for RelatedVec<T> {
    fn eq(&self, _other: &Self) -> bool {
        // skip comparison of related collections in tests
        true
    }
}

// helper implementations
enum AsyncModelStore<M: Model> {
    AlreadyLoaded(M),
    ToBeLoaded(Box<dyn AsyncModelLoader<M>>),
}

impl<T: Model + Debug> Debug for AsyncModelStore<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AlreadyLoaded(model) => f.debug_tuple("AlreadyLoaded").field(model).finish(),
            Self::ToBeLoaded(_) => f.debug_tuple("ToBeLoaded").finish(),
        }
    }
}

enum AsyncVecStore<T> {
    AlreadyLoaded(Vec<T>),
    ToBeLoaded(Box<dyn AsyncVecLoader<T>>),
}

impl<T: Debug> Debug for AsyncVecStore<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AlreadyLoaded(models) => f.debug_tuple("AlreadyLoaded").field(models).finish(),
            Self::ToBeLoaded(_) => f.debug_tuple("ToBeLoaded").finish(),
        }
    }
}

/// Loader shared by a batch of [`Related`] and [`RelatedVec`] instances: the first `load`
/// resolves every id of the batch with a single call to the underlying [`AsyncBatchLoader`], all
/// further loads (of any member of the batch) are served from the cached result.
pub struct BatchModelLoader<K, V> {
    ids: Vec<K>,
    loader: Box<dyn AsyncBatchLoader<K, V>>,
    cache: OnceCell<HashMap<K, V>>,
}

impl<K: Eq + Hash, V> BatchModelLoader<K, V> {
    pub fn new(
        ids: impl IntoIterator<Item = K>,
        loader: impl AsyncBatchLoader<K, V> + 'static,
    ) -> Arc<Self> {
        let deduplicated: HashSet<_> = HashSet::from_iter(ids);
        Arc::new(Self {
            ids: deduplicated.into_iter().collect(),
            loader: Box::new(loader),
            cache: OnceCell::new(),
        })
    }

    async fn get(&self, id: &K) -> Result<Option<&V>, DataLayerError> {
        let by_id = self
            .cache
            .get_or_try_init(|| self.loader.load(&self.ids))
            .await?;
        Ok(by_id.get(id))
    }
}

#[async_trait::async_trait]
impl<M: Model + Clone + Send + Sync> AsyncModelLoader<M> for Arc<BatchModelLoader<M::Id, M>>
where
    M::Id: Eq + Hash + Send + Sync,
{
    async fn load(&self, id: &M::Id) -> Result<M, DataLayerError> {
        self.get(id)
            .await?
            .cloned()
            .ok_or_else(|| DataLayerError::MissingRequiredRelation {
                relation: std::any::type_name::<M>(),
                id: id.to_string(),
            })
    }
}

impl<K, T> BatchModelLoader<K, Vec<T>> {
    pub fn list(self: &Arc<Self>, key: K) -> BatchList<K, T> {
        BatchList {
            key,
            batch: self.clone(),
        }
    }
}

pub struct BatchList<K, T> {
    key: K,
    batch: Arc<BatchModelLoader<K, Vec<T>>>,
}

#[async_trait::async_trait]
impl<K, T> AsyncVecLoader<T> for BatchList<K, T>
where
    K: Eq + Hash + Send + Sync,
    T: Clone + Send + Sync,
{
    async fn load(&self) -> Result<Vec<T>, DataLayerError> {
        Ok(self
            .batch
            .get(&self.key)
            .await?
            .cloned()
            .unwrap_or_default())
    }
}

// AsyncVecLoader wrapper
struct ModelsLoaderWrapper<M: Model> {
    ids: Vec<M::Id>,
    loader: Box<dyn AsyncModelsLoader<M>>,
}

#[async_trait::async_trait]
impl<M: Model> AsyncVecLoader<M> for ModelsLoaderWrapper<M>
where
    M::Id: Send + Sync,
{
    async fn load(&self) -> Result<Vec<M>, DataLayerError> {
        self.loader.load(&self.ids).await
    }
}

#[cfg(test)]
mod tests {
    use shared_types::ClaimSchemaId;
    use similar_asserts::assert_eq;
    use uuid::Uuid;

    use super::*;
    use crate::model::claim_schema::ClaimSchema;
    use crate::repository::claim_schema_repository::{
        ClaimSchemaRepository, MockClaimSchemaRepository,
    };
    use crate::repository::organisation_repository::{
        MockOrganisationRepository, OrganisationRepository,
    };
    use crate::service::test_utilities::{dummy_claim_schema, dummy_organisation};

    #[tokio::test]
    async fn test_from() {
        let id = Uuid::new_v4().into();
        let data = Related::from(dummy_organisation(Some(id)));
        assert_eq!(data.as_ref().await.unwrap().id, id);

        let claim_schema = dummy_claim_schema();
        let data = RelatedVec::from(vec![claim_schema.clone()]);
        assert_eq!(data.as_ref().await.unwrap().as_ref(), &[claim_schema]);
    }

    #[tokio::test]
    async fn test_organisation_repository() {
        let mut repository = MockOrganisationRepository::new();
        repository
            .expect_get_organisation()
            .once()
            .return_once(|id| Ok(dummy_organisation(Some(*id))));

        let repository: Arc<dyn OrganisationRepository> = Arc::new(repository);

        let id = Uuid::new_v4().into();
        let related = Related::new(id, repository);
        assert_eq!(related.id(), id);
        let organsation = related.as_ref().await.unwrap();
        assert_eq!(organsation.id, id);
    }

    #[tokio::test]
    async fn test_batch_model_loader_loads_whole_batch_once() {
        let ids: Vec<ClaimSchemaId> = (0..3).map(|_| Uuid::new_v4().into()).collect();

        let mut repository = MockClaimSchemaRepository::new();
        repository
            .expect_get_claim_schema_list()
            .once()
            .returning(|ids| {
                Ok(ids
                    .into_iter()
                    .map(|id| ClaimSchema {
                        id,
                        ..dummy_claim_schema()
                    })
                    .collect())
            });
        let repository: Arc<dyn ClaimSchemaRepository> = Arc::new(repository);

        // the same id twice, to verify deduplication
        let loader = BatchModelLoader::new([ids[0], ids[1], ids[2], ids[0]], repository);
        let related: Vec<Related<ClaimSchema>> = ids
            .iter()
            .map(|id| Related::new(*id, loader.clone()))
            .collect();

        for (related, id) in related.iter().zip(&ids) {
            // available without loading
            assert_eq!(related.id(), *id);
            // `once()` on the mock asserts that all three resolve from a single batched call
            assert_eq!(related.as_ref().await.unwrap().id, *id);
        }
    }

    struct ClaimSchemasByKey {
        calls: std::sync::atomic::AtomicUsize,
        by_key: HashMap<u8, Vec<ClaimSchema>>,
    }

    #[async_trait::async_trait]
    impl AsyncBatchLoader<u8, Vec<ClaimSchema>> for Arc<ClaimSchemasByKey> {
        async fn load(&self, keys: &[u8]) -> Result<HashMap<u8, Vec<ClaimSchema>>, DataLayerError> {
            self.calls
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let mut keys = keys.to_vec();
            keys.sort();
            assert_eq!(keys, [1, 2]);
            Ok(self.by_key.clone())
        }
    }

    #[tokio::test]
    async fn test_batch_model_loader_of_lists_loads_whole_batch_once() {
        let claim_schema = dummy_claim_schema();
        let loader = Arc::new(ClaimSchemasByKey {
            calls: Default::default(),
            by_key: HashMap::from([(1, vec![claim_schema.clone()])]),
        });

        // the same key twice, to verify deduplication
        let batch = BatchModelLoader::new([1, 2, 1], loader.clone());
        let with_schemas = RelatedVec::new(batch.list(1));
        let without_schemas = RelatedVec::new(batch.list(2));

        assert_eq!(
            with_schemas.as_ref().await.unwrap().as_ref(),
            std::slice::from_ref(&claim_schema)
        );
        assert!(without_schemas.as_ref().await.unwrap().is_empty());
        assert_eq!(loader.calls.load(std::sync::atomic::Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn test_claim_schemas_repository() {
        let mut repository = MockClaimSchemaRepository::new();
        repository
            .expect_get_claim_schema_list()
            .once()
            .return_once(|_| Ok(vec![]));

        let repository: Arc<dyn ClaimSchemaRepository> = Arc::new(repository);

        let id = Uuid::new_v4().into();
        let related: RelatedVec<ClaimSchema> = RelatedVec::from_ids(vec![id], repository);
        let claim_schemas = related.as_ref().await.unwrap();
        assert_eq!(claim_schemas.len(), 0);
    }
}
