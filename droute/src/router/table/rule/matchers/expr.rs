// Copyright 2021 LEXUGE
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

use super::{MatchError, Matcher};
use crate::{router::table::State, AsyncTryInto};
use async_trait::async_trait;
use pest::{
    iterators::{Pair, Pairs},
    Parser,
};
use pest_derive::Parser;
use serde::Deserialize;
use std::iter::Iterator;
use thiserror::Error;

#[allow(clippy::enum_variant_names)]
#[derive(Error, Debug)]
pub enum ExprError {
    #[error(transparent)]
    PestError(#[from] pest::error::Error<Rule>),

    #[error(transparent)]
    RonError(#[from] ron::Error),

    #[error(transparent)]
    MatchError(#[from] MatchError),
}

#[derive(Parser)]
#[grammar = "router/table/rule/matchers/expr.pest"] // relative to src
pub struct ExprParser;

impl ExprParser {
    pub fn build_node<M>(&self, input: &str) -> Result<Node<BuilderPrimitive<M>>, ExprError>
    where
        for<'a> M: Deserialize<'a> + AsyncTryInto<Box<dyn Matcher>, Error = MatchError>,
    {
        // There should only be one prog
        let prog = ExprParser::parse(Rule::Program, input)?.next().unwrap();
        build_node_from_term::<M>(prog)
    }
}

fn build_node_from_expr<M>(expr: Pair<Rule>) -> Result<Node<BuilderPrimitive<M>>, ExprError>
where
    for<'a> M: Deserialize<'a> + AsyncTryInto<Box<dyn Matcher>, Error = MatchError>,
{
    // Expr here can either be negexpr or orexpr
    let expr = expr.into_inner().next().unwrap();

    Ok(match expr.as_rule() {
        Rule::NegExpr => Node::Neg(Box::new(build_node_from_term::<M>(
            expr.into_inner().next().unwrap(),
        )?)),
        Rule::OrExpr => {
            let mut operands = expr.into_inner();
            // There is only one operand which is andexpr
            if operands.clone().count() == 1 {
                build_node_from_andexpr::<M>(operands.next().unwrap().into_inner())?
            } else {
                // This is a real orexpr
                let mut v = Vec::new();
                for x in operands {
                    v.push(build_node_from_andexpr::<M>(x.into_inner())?);
                }
                Node::Or(v)
            }
        }
        _ => unreachable!(),
    })
}

fn build_node_from_term<M>(term: Pair<Rule>) -> Result<Node<BuilderPrimitive<M>>, ExprError>
where
    for<'a> M: Deserialize<'a> + AsyncTryInto<Box<dyn Matcher>, Error = MatchError>,
{
    Ok(match term.as_rule() {
        Rule::True => Node::None(BuilderPrimitive::Bool(true)),
        Rule::False => Node::None(BuilderPrimitive::Bool(false)),
        Rule::Ron => Node::None(BuilderPrimitive::MatcherBuilder(ron::from_str::<M>(
            term.as_str(),
        )?)),
        Rule::Expr => build_node_from_expr(term)?,
        _ => unreachable!(),
    })
}

fn build_node_from_andexpr<M>(
    mut andexpr_operands: Pairs<Rule>,
) -> Result<Node<BuilderPrimitive<M>>, ExprError>
where
    for<'a> M: Deserialize<'a> + AsyncTryInto<Box<dyn Matcher>, Error = MatchError>,
{
    // In this case, andexpr wraps around a term
    Ok(if andexpr_operands.clone().count() == 1 {
        build_node_from_term::<M>(andexpr_operands.next().unwrap())?
    } else {
        // This is a real andexpr...
        let mut v = Vec::new();
        for x in andexpr_operands {
            v.push(build_node_from_term::<M>(x)?)
        }
        Node::And(v)
    })
}

pub enum Primitive {
    Bool(bool),
    Matcher(Box<dyn Matcher>),
}

#[derive(Debug, PartialEq, Eq)]
pub enum BuilderPrimitive<M>
where
    for<'a> M: Deserialize<'a> + AsyncTryInto<Box<dyn Matcher>, Error = MatchError>,
{
    Bool(bool),
    MatcherBuilder(M),
}

impl Primitive {
    pub fn eval(&self, state: &State) -> bool {
        match self {
            Self::Bool(bl) => *bl,
            Self::Matcher(m) => m.matches(state),
        }
    }
}

// Kinda like an AST
#[derive(Debug, PartialEq, Eq)]
pub enum Node<P> {
    And(Vec<Self>),
    Or(Vec<Self>),
    Neg(Box<Self>),
    None(P),
}

impl<M> Node<BuilderPrimitive<M>>
where
    for<'a> M: Deserialize<'a> + AsyncTryInto<Box<dyn Matcher>, Error = MatchError>,
{
    pub fn trim(self) -> Self {
        match self {
            Node::And(mut v) => {
                // A flag indicating all elements are true
                let mut flag = true;
                v = v.into_iter().map(|x| x.trim()).collect();
                for x in &v {
                    match x {
                        Node::None(BuilderPrimitive::Bool(false)) => {
                            return Node::None(BuilderPrimitive::Bool(false));
                        }
                        // Do nothing on true, if later we encounter impure components, we would again return ourself. However, if we always do nothing, all primitives are false. In that case, we return true.
                        Node::None(BuilderPrimitive::Bool(true)) => {}
                        // If impure, then mark the flag false
                        _ => flag = false,
                    }
                }
                if flag {
                    Node::None(BuilderPrimitive::Bool(true))
                } else {
                    Node::And(v)
                }
            }
            Node::Or(mut v) => {
                // A flag indicating all elements are false
                let mut flag = true;
                v = v.into_iter().map(|x| x.trim()).collect();
                for x in &v {
                    match x {
                        Node::None(BuilderPrimitive::Bool(true)) => {
                            return Node::None(BuilderPrimitive::Bool(true));
                        }
                        // Do nothing on false, if later we encounter impure components, we would again return ourself. However, if we always do nothing, all primitives are false. In that case, we return true.
                        Node::None(BuilderPrimitive::Bool(false)) => {}
                        // If impure, then mark the flag false
                        _ => flag = false,
                    }
                }
                if flag {
                    Node::None(BuilderPrimitive::Bool(false))
                } else {
                    Node::Or(v)
                }
            }
            Node::Neg(op) => match op.trim() {
                Node::None(BuilderPrimitive::Bool(bl)) => Node::None(BuilderPrimitive::Bool(!bl)),
                Node::None(BuilderPrimitive::MatcherBuilder(m)) => {
                    Node::None(BuilderPrimitive::MatcherBuilder(m))
                }
                Node::And(v) => Node::And(v),
                Node::Or(v) => Node::Or(v),
                Node::Neg(op) => Node::Neg(op),
            },
            Node::None(_) => self,
        }
    }

    #[cfg(test)]
    fn pure_unwrap(&self) -> bool {
        match self {
            Node::None(BuilderPrimitive::Bool(bl)) => *bl,
            _ => panic!("not a primitive pure node"),
        }
    }
}

impl Matcher for Node<Primitive> {
    fn matches(&self, state: &State) -> bool {
        match self {
            Node::And(v) => v.iter().map(|x| x.matches(state)).all(|x| x),
            Node::Or(v) => v.iter().map(|x| x.matches(state)).any(|x| x),
            Node::Neg(op) => !op.matches(state),
            Node::None(prim) => prim.eval(state),
        }
    }
}

#[async_trait]
impl<M> AsyncTryInto<Node<Primitive>> for Node<BuilderPrimitive<M>>
where
    for<'a> M: Deserialize<'a> + AsyncTryInto<Box<dyn Matcher>, Error = MatchError>,
{
    type Error = MatchError;

    async fn async_try_into(self) -> Result<Node<Primitive>, Self::Error> {
        Ok(match self {
            Node::And(v) => {
                let mut v_prime = Vec::new();
                for x in v {
                    v_prime.push(x.async_try_into().await?)
                }
                Node::And(v_prime)
            }
            Node::Or(v) => {
                let mut v_prime = Vec::new();
                for x in v {
                    v_prime.push(x.async_try_into().await?)
                }
                Node::Or(v_prime)
            }
            Node::Neg(op) => Node::Neg(Box::new(op.async_try_into().await?)),
            Node::None(BuilderPrimitive::Bool(bl)) => Node::None(Primitive::Bool(bl)),
            Node::None(BuilderPrimitive::MatcherBuilder(m)) => {
                Node::None(Primitive::Matcher(m.async_try_into().await?))
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{Node, Primitive};
    use crate::{
        matchers::{
            builder::BuiltinMatcherBuilders,
            expr::{BuilderPrimitive, ExprParser},
            MatchError, Matcher,
        },
        router::table::State,
        AsyncTryInto,
    };
    use async_trait::async_trait;
    use serde::Deserialize;

    #[derive(Deserialize, Debug, PartialEq)]
    struct DummyMatcher;

    impl Matcher for DummyMatcher {
        fn matches(&self, _: &State) -> bool {
            false
        }
    }

    #[async_trait]
    impl AsyncTryInto<Box<dyn Matcher>> for DummyMatcher {
        type Error = MatchError;
        async fn async_try_into(self) -> Result<Box<dyn Matcher>, Self::Error> {
            Err(MatchError::Other("foo".to_string()))
        }
    }

    #[test]
    fn basic() {
        assert_eq!(
            Node::None(Primitive::Bool(true)).matches(&State::default()),
            true
        );
        assert_eq!(
            Node::And(vec![
                Node::None(Primitive::Bool(true)),
                Node::None(Primitive::Bool(false)),
                Node::None(Primitive::Bool(true))
            ])
            .matches(&State::default()),
            false
        );
        assert_eq!(
            Node::And(vec![
                Node::Neg(Box::new(Node::None(Primitive::Bool(false)))),
                Node::Or(vec![
                    Node::None(Primitive::Bool(false)),
                    Node::None(Primitive::Bool(true))
                ])
            ])
            .matches(&State::default()),
            true
        );
    }

    #[tokio::test]
    async fn trim() {
        assert_eq!(
            ExprParser
                .build_node::<BuiltinMatcherBuilders>(
                    r#"(true && false || true && true || true && false)"#
                )
                .unwrap()
                .trim()
                .async_try_into()
                .await
                .unwrap()
                .matches(&State::default()),
            ExprParser
                .build_node::<BuiltinMatcherBuilders>(
                    r#"(true && false || true && true || true && false)"#
                )
                .unwrap()
                .async_try_into()
                .await
                .unwrap()
                .matches(&State::default()),
        );

        assert_eq!(
            ExprParser
                .build_node::<BuiltinMatcherBuilders>(
                    r#"(true && (false || true) && (true || true) && false)"#
                )
                .unwrap()
                .trim()
                .async_try_into()
                .await
                .unwrap()
                .matches(&State::default()),
            ExprParser
                .build_node::<BuiltinMatcherBuilders>(
                    r#"(true && (false || true) && (true || true) && false)"#
                )
                .unwrap()
                .async_try_into()
                .await
                .unwrap()
                .matches(&State::default()),
        );

        // All true and
        assert_eq!(
            Node::And(vec![
                Node::Neg(Box::new(Node::None(
                    BuilderPrimitive::<DummyMatcher>::Bool(false)
                ))),
                Node::None(BuilderPrimitive::Bool(true)),
                Node::None(BuilderPrimitive::Bool(true)),
            ])
            .trim()
            .pure_unwrap(),
            true
        );

        assert_eq!(
            Node::And(vec![
                Node::None(BuilderPrimitive::<DummyMatcher>::Bool(true)),
                Node::None(BuilderPrimitive::Bool(false)),
                Node::None(BuilderPrimitive::Bool(true)),
            ])
            .trim()
            .pure_unwrap(),
            false
        );

        // Short-circuited
        assert_eq!(
            Node::Or(vec![
                Node::None(BuilderPrimitive::<DummyMatcher>::MatcherBuilder(
                    DummyMatcher
                )),
                Node::None(BuilderPrimitive::Bool(true)),
            ])
            .trim()
            .pure_unwrap(),
            true
        );

        // Ireducible
        assert_eq!(
            Node::And(vec![
                Node::None(BuilderPrimitive::<DummyMatcher>::MatcherBuilder(
                    DummyMatcher
                )),
                Node::None(BuilderPrimitive::Bool(true)),
            ])
            .trim(),
            Node::And(vec![
                Node::None(BuilderPrimitive::<DummyMatcher>::MatcherBuilder(
                    DummyMatcher
                )),
                Node::None(BuilderPrimitive::Bool(true)),
            ])
        );

        assert_eq!(
            Node::And(vec![
                Node::None(BuilderPrimitive::<DummyMatcher>::Bool(true)),
                // false
                Node::Neg(Box::new(Node::Or(vec![
                    Node::None(BuilderPrimitive::Bool(true)),
                    Node::None(BuilderPrimitive::Bool(false))
                ]))),
                Node::None(BuilderPrimitive::Bool(true)),
            ])
            .trim()
            .pure_unwrap(),
            false,
        );
    }

    #[tokio::test]
    async fn parser() {
        assert_eq!(
            ExprParser
                .build_node::<BuiltinMatcherBuilders>("true")
                .unwrap()
                .async_try_into()
                .await
                .unwrap()
                .matches(&State::default()),
            true
        );
        assert_eq!(
            ExprParser
                .build_node::<BuiltinMatcherBuilders>("((true || (!false)) && false)")
                .unwrap()
                .async_try_into()
                .await
                .unwrap()
                .matches(&State::default()),
            false
        );
        assert_eq!(
            ExprParser
                .build_node::<BuiltinMatcherBuilders>(
                    "(true && false || true && true || true && false)"
                )
                .unwrap()
                .async_try_into()
                .await
                .unwrap()
                .matches(&State::default()),
            true
        );

        assert_eq!(
            ExprParser
                .build_node::<DummyMatcher>("true && false || true && (true || true) && false")
                .unwrap(),
            Node::Or(vec![
                Node::And(vec![
                    Node::None(BuilderPrimitive::Bool(true)),
                    Node::None(BuilderPrimitive::Bool(false))
                ]),
                Node::And(vec![
                    Node::None(BuilderPrimitive::Bool(true)),
                    Node::Or(vec![
                        Node::None(BuilderPrimitive::Bool(true)),
                        Node::None(BuilderPrimitive::Bool(true))
                    ]),
                    Node::None(BuilderPrimitive::Bool(false)),
                ]),
            ])
        );

        // Redundant brackets should not alter the syntax tree
        assert_eq!(
            ExprParser
                .build_node::<DummyMatcher>("true && false || true && (true || true) && false")
                .unwrap(),
            ExprParser
                .build_node::<DummyMatcher>(
                    "(((true && false) || true && (true || true) && ((false))))"
                )
                .unwrap(),
        );
    }
}
