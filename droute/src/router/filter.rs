use super::parser::Rule;
use crate::error::Result;
use dmatcher::Dmatcher;
use log::*;
use tokio::{fs::File, prelude::*};
// use tokio_compat_02::FutureExt;

pub struct Filter {
    default_tag: usize,
    matcher: Dmatcher<usize>,
}

impl Filter {
    async fn insert_rules(rules: Vec<Rule>) -> Result<(Dmatcher<usize>, Vec<usize>)> {
        let mut matcher = Dmatcher::new();
        let mut v = vec![];
        for r in rules {
            let mut file = File::open(r.path).await?;
            let mut data = String::new();
            file.read_to_string(&mut data).await?;
            matcher.insert_lines(data, r.dst)?;
            v.push(r.dst);
        }
        Ok((matcher, v))
    }

    pub async fn new(default_tag: usize, rules: Vec<Rule>) -> Result<(Self, Vec<usize>)> {
        let (matcher, dsts) = Self::insert_rules(rules).await?;
        Ok((
            Self {
                default_tag,
                matcher,
            },
            dsts,
        ))
    }

    pub fn default_tag(&self) -> usize {
        self.default_tag
    }

    pub fn get_upstream(&self, domain: &str) -> Result<usize> {
        Ok(match self.matcher.matches(domain)? {
            Some(u) => {
                info!("{} routed via upstream with tag {}", domain, u);
                u
            }
            None => {
                info!(
                    "{} routed via upstream with default tag {}",
                    domain, self.default_tag
                );
                self.default_tag
            }
        })
    }
}
