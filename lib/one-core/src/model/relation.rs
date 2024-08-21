use std::fmt::Debug;
use std::sync::Arc;
use tokio::sync::Mutex;

// TODO: decide error type
use crate::repository::error::DataLayerError;

pub trait Model {
    type Id: Clone + Debug;
    fn id(&self) -> &Self::Id;
}

pub trait RelatedIdMarker {
    type Id: Clone + Debug;
}

impl<TModel: Model> RelatedIdMarker for TModel {
    type Id = TModel::Id;
}

impl<T> RelatedIdMarker for Vec<T> {
    type Id = ();
}

#[async_trait::async_trait]
pub trait RelationLoader<T: RelatedIdMarker>: Send + Sync {
    async fn load(&self, id: &T::Id) -> Result<T, DataLayerError>;
}

pub struct FailingRelationLoader;
#[async_trait::async_trait]
impl<T: RelatedIdMarker> RelationLoader<T> for FailingRelationLoader {
    async fn load(&self, _: &T::Id) -> Result<T, DataLayerError> {
        Err(DataLayerError::Db(anyhow::anyhow!(
            "ID only relation, model {} not available",
            std::any::type_name::<T>()
        )))
    }
}

enum Lazy<T> {
    Present(T),
    Loader(Box<dyn RelationLoader<T>>),
}

impl<T: Debug> Debug for Lazy<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Present(model) => f.debug_tuple("Present").field(model).finish(),
            Self::Loader(_) => f.debug_tuple("Loader").finish(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct LazyLoaded<T: RelatedIdMarker> {
    loader: Arc<Mutex<Lazy<T>>>,
    id: T::Id,
}

impl<T: RelatedIdMarker> LazyLoaded<T> {
    fn new(loader: Box<dyn RelationLoader<T>>, id: T::Id) -> Self {
        Self {
            loader: Arc::new(Mutex::new(Lazy::Loader(loader))),
            id,
        }
    }
}

#[derive(Clone, Debug)]
pub enum Related<T: RelatedIdMarker> {
    Provided(T),
    Lazy(LazyLoaded<T>),
}

impl<T: RelatedIdMarker + Clone> Related<T> {
    pub async fn get(&self) -> Result<T, DataLayerError> {
        match self {
            Related::Provided(data) => Ok(data.to_owned()),
            Related::Lazy(lazy) => {
                let mut guard = lazy.loader.lock().await;
                Ok(match &*guard {
                    Lazy::Present(data) => data.to_owned(),
                    Lazy::Loader(loader) => {
                        let data = loader.load(&lazy.id).await?;
                        *guard = Lazy::Present(data.to_owned());
                        data
                    }
                })
            }
        }
    }
}

impl<T: RelatedIdMarker> Related<T>
where
    T::Id: Default,
{
    pub fn from_loader_no_id(loader: Box<dyn RelationLoader<T>>) -> Self {
        Self::Lazy(LazyLoaded::new(loader, T::Id::default()))
    }
}

impl<TModel: Model> Related<TModel> {
    pub fn from_loader(id: TModel::Id, loader: Box<dyn RelationLoader<TModel>>) -> Self {
        Self::Lazy(LazyLoaded::new(loader, id))
    }

    #[cfg(any(test, feature = "mock"))]
    pub fn from_id_only(id: impl Into<TModel::Id>) -> Self {
        Self::Lazy(LazyLoaded::new(Box::new(FailingRelationLoader), id.into()))
    }

    pub fn id(&self) -> &TModel::Id {
        match self {
            Related::Provided(model) => model.id(),
            Related::Lazy(lazy) => &lazy.id,
        }
    }
}

impl<T: RelatedIdMarker> From<T> for Related<T> {
    fn from(data: T) -> Self {
        Self::Provided(data)
    }
}

impl<T: RelatedIdMarker + Default> Default for Related<T> {
    fn default() -> Self {
        Self::Provided(T::default())
    }
}

impl<T: RelatedIdMarker + PartialEq> PartialEq for Related<T>
where
    T::Id: PartialEq,
{
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Provided(l0), Self::Provided(r0)) => l0 == r0,
            (Self::Lazy(l0), Self::Lazy(r0)) => l0.id == r0.id,
            _ => false,
        }
    }
}

impl<T: RelatedIdMarker + Eq> Eq for Related<T> where T::Id: PartialEq {}

impl<T, Collection: FromIterator<T> + RelatedIdMarker> FromIterator<T> for Related<Collection> {
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
        Self::Provided(Collection::from_iter(iter))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone)]
    struct WithModel {
        id: i32,
        value: usize,
    }

    impl Model for WithModel {
        type Id = i32;
        fn id(&self) -> &Self::Id {
            &self.id
        }
    }

    #[derive(Clone)]
    struct WithoutModel {
        value: usize,
    }

    #[tokio::test]
    async fn test_from() {
        let data = Related::from(vec![WithoutModel { value: 1 }]);
        assert_eq!(data.get().await.unwrap().first().unwrap().value, 1);
    }

    #[tokio::test]
    async fn test_default() {
        let data: Related<Vec<WithoutModel>> = Default::default();
        assert_eq!(data.get().await.unwrap().len(), 0);
    }

    #[tokio::test]
    async fn test_collect() {
        let data: Related<Vec<WithoutModel>> =
            vec![WithoutModel { value: 1 }].into_iter().collect();
        assert_eq!(data.get().await.unwrap().first().unwrap().value, 1);
    }

    #[tokio::test]
    async fn test_from_loader_no_id() {
        struct WithoutModelLoader;
        #[async_trait::async_trait]
        impl RelationLoader<Vec<WithoutModel>> for WithoutModelLoader {
            async fn load(&self, _: &()) -> Result<Vec<WithoutModel>, DataLayerError> {
                Ok(vec![WithoutModel { value: 1 }])
            }
        }

        let data = Related::from_loader_no_id(Box::new(WithoutModelLoader));
        assert_eq!(data.get().await.unwrap().first().unwrap().value, 1);
    }

    #[tokio::test]
    async fn test_from_loader_no_id_failing() {
        struct FailingLoader;
        #[async_trait::async_trait]
        impl RelationLoader<Vec<WithoutModel>> for FailingLoader {
            async fn load(&self, _: &()) -> Result<Vec<WithoutModel>, DataLayerError> {
                Err(DataLayerError::MappingError)
            }
        }

        let data = Related::from_loader_no_id(Box::new(FailingLoader));
        assert!(matches!(
            data.get().await,
            Err(DataLayerError::MappingError)
        ));
    }

    #[tokio::test]
    async fn test_from_model() {
        let data = Related::from(WithModel { id: 1, value: 2 });
        assert_eq!(data.id(), &1);
        let data = data.get().await.unwrap();
        assert_eq!(data.id, 1);
        assert_eq!(data.value, 2);
    }

    #[tokio::test]
    async fn test_from_loader_with_id() {
        struct WithModelLoader;
        #[async_trait::async_trait]
        impl RelationLoader<WithModel> for WithModelLoader {
            async fn load(&self, _: &i32) -> Result<WithModel, DataLayerError> {
                Ok(WithModel { id: 1, value: 2 })
            }
        }

        let data = Related::from_loader(1, Box::new(WithModelLoader));
        assert_eq!(data.id(), &1);
        let data = data.get().await.unwrap();
        assert_eq!(data.id, 1);
        assert_eq!(data.value, 2);
    }

    #[tokio::test]
    async fn test_from_id_only() {
        let data = Related::<WithModel>::from_id_only(1);
        assert_eq!(data.id(), &1);
        assert!(data.get().await.is_err());
    }
}
