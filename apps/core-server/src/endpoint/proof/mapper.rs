use one_core::model::proof::SortableProofColumn;

use super::dto::SortableProofColumnRestEnum;

impl From<SortableProofColumnRestEnum> for SortableProofColumn {
    fn from(value: SortableProofColumnRestEnum) -> Self {
        match value {
            SortableProofColumnRestEnum::ProofSchemaName => Self::SchemaName,
            SortableProofColumnRestEnum::VerifierDid => Self::VerifierDid,
            SortableProofColumnRestEnum::CreatedDate => Self::CreatedDate,
            SortableProofColumnRestEnum::State => Self::State,
        }
    }
}
