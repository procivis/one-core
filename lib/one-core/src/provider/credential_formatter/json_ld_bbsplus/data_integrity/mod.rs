use std::collections::HashSet;

use json_ld::rdf_types;
use sophia_api::quad::Spog;

use crate::util::rdf_canonization::TermAdapter;

mod base_proof;
pub use base_proof::*;

mod derived_proof;
pub use derived_proof::*;

mod verify;
pub use verify::*;

mod canonicalize;
mod selection;
mod skolemize;

#[cfg(test)]
pub mod test_data;

// helper trait for converting nquad representation to a string
trait NQuadLines {
    fn nquad_lines(&self) -> impl Iterator<Item = String>;
}

impl NQuadLines for HashSet<Spog<TermAdapter>> {
    fn nquad_lines(&self) -> impl Iterator<Item = String> {
        use rdf_types::RdfDisplay;

        self.iter().map(|(triple, graph)| {
            let [TermAdapter(s), TermAdapter(p), TermAdapter(o)] = triple;

            if let Some(TermAdapter(g)) = graph {
                format!(
                    "{} {} {} {} .\n",
                    s.rdf_display(),
                    p.rdf_display(),
                    o.rdf_display(),
                    g.rdf_display()
                )
            } else {
                format!(
                    "{} {} {} .\n",
                    s.rdf_display(),
                    p.rdf_display(),
                    o.rdf_display()
                )
            }
        })
    }
}
