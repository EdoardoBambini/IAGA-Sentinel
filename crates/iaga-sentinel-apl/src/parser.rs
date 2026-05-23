//! Recursive-descent parser for APL.
//!
//! Precedence (low → high):
//!   or
//!   and
//!   not              (prefix)
//!   == != < <= > >=
//!   in / not in
//!   primary (literal | call | path | parenthesized)

use crate::ast::*;
use crate::errors::{AplError, Result};
use crate::lexer::{tokenize, Token};

struct P {
    toks: Vec<(Token, u32, u32)>,
    pos: usize,
}

pub fn parse(src: &str) -> Result<Program> {
    let toks = tokenize(src)?;
    let mut p = P { toks, pos: 0 };
    let mut policies = Vec::new();
    while !p.eof() {
        policies.push(p.parse_policy()?);
    }
    Ok(Program { policies })
}

impl P {
    fn eof(&self) -> bool {
        self.pos >= self.toks.len()
    }

    fn peek(&self) -> Option<&Token> {
        self.toks.get(self.pos).map(|(t, _, _)| t)
    }

    fn peek_lc(&self) -> (u32, u32) {
        self.toks
            .get(self.pos)
            .map(|(_, l, c)| (*l, *c))
            .unwrap_or((0, 0))
    }

    fn advance(&mut self) -> Option<Token> {
        let t = self.toks.get(self.pos).cloned()?;
        self.pos += 1;
        Some(t.0)
    }

    fn err<T>(&self, msg: impl Into<String>) -> Result<T> {
        let (line, col) = self.peek_lc();
        Err(AplError::Parse {
            line,
            col,
            msg: msg.into(),
        })
    }

    fn expect(&mut self, expected: Token, ctx: &str) -> Result<()> {
        match self.advance() {
            Some(t) if std::mem::discriminant(&t) == std::mem::discriminant(&expected) => Ok(()),
            Some(other) => self.err(format!("expected {} (got {:?})", ctx, other)),
            None => self.err(format!("expected {}, got EOF", ctx)),
        }
    }

    fn parse_policy(&mut self) -> Result<Policy> {
        // `policy "name" { when <expr> then <action> }`
        self.expect(Token::Policy, "`policy`")?;
        let name = match self.advance() {
            Some(Token::Str(s)) => s,
            _ => return self.err("expected policy name string"),
        };
        self.expect(Token::LBrace, "`{`")?;
        self.expect(Token::When, "`when`")?;
        let when = self.parse_expr()?;
        self.expect(Token::Then, "`then`")?;
        let action = self.parse_action()?;
        self.expect(Token::RBrace, "`}`")?;
        Ok(Policy { name, when, action })
    }

    fn parse_action(&mut self) -> Result<Action> {
        let verdict = match self.advance() {
            Some(Token::Allow) => Verdict::Allow,
            Some(Token::Review) => Verdict::Review,
            Some(Token::Block) => Verdict::Block,
            Some(other) => return self.err(format!("expected verdict (got {:?})", other)),
            None => return self.err("expected verdict, got EOF"),
        };
        let mut reason = None;
        let mut evidence = None;
        while matches!(self.peek(), Some(Token::Comma)) {
            self.advance();
            match self.advance() {
                Some(Token::Reason) => {
                    self.expect(Token::Eq, "`=`")?;
                    match self.advance() {
                        Some(Token::Str(s)) => reason = Some(s),
                        _ => return self.err("reason= expects string"),
                    }
                }
                Some(Token::Evidence) => {
                    self.expect(Token::Eq, "`=`")?;
                    evidence = Some(self.parse_expr()?);
                }
                Some(other) => {
                    return self.err(format!("unknown action attr {:?}", other));
                }
                None => return self.err("expected action attr, got EOF"),
            }
        }
        Ok(Action {
            verdict,
            reason,
            evidence,
        })
    }

    // ── expressions, precedence climbing ──

    fn parse_expr(&mut self) -> Result<Expr> {
        self.parse_or()
    }

    fn parse_or(&mut self) -> Result<Expr> {
        let mut left = self.parse_and()?;
        while matches!(self.peek(), Some(Token::Or)) {
            self.advance();
            let right = self.parse_and()?;
            left = Expr::Binary(BinOp::Or, Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_and(&mut self) -> Result<Expr> {
        let mut left = self.parse_not()?;
        while matches!(self.peek(), Some(Token::And)) {
            self.advance();
            let right = self.parse_not()?;
            left = Expr::Binary(BinOp::And, Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_not(&mut self) -> Result<Expr> {
        if matches!(self.peek(), Some(Token::Not)) {
            self.advance();
            let inner = self.parse_not()?;
            return Ok(Expr::Unary(UnOp::Not, Box::new(inner)));
        }
        self.parse_compare()
    }

    fn parse_compare(&mut self) -> Result<Expr> {
        let left = self.parse_membership()?;
        let op = match self.peek() {
            Some(Token::EqEq) => Some(BinOp::Eq),
            Some(Token::NotEq) => Some(BinOp::Neq),
            Some(Token::Lt) => Some(BinOp::Lt),
            Some(Token::Gt) => Some(BinOp::Gt),
            Some(Token::LtEq) => Some(BinOp::Le),
            Some(Token::GtEq) => Some(BinOp::Ge),
            _ => None,
        };
        if let Some(op) = op {
            self.advance();
            let right = self.parse_membership()?;
            return Ok(Expr::Binary(op, Box::new(left), Box::new(right)));
        }
        Ok(left)
    }

    fn parse_membership(&mut self) -> Result<Expr> {
        let left = self.parse_primary()?;
        // `x in y` or `x not in y`
        match self.peek() {
            Some(Token::In) => {
                self.advance();
                let right = self.parse_primary()?;
                Ok(Expr::Membership {
                    not: false,
                    needle: Box::new(left),
                    haystack: Box::new(right),
                })
            }
            Some(Token::Not) => {
                // could be `not in` (membership) — lookahead:
                let save = self.pos;
                self.advance();
                if matches!(self.peek(), Some(Token::In)) {
                    self.advance();
                    let right = self.parse_primary()?;
                    Ok(Expr::Membership {
                        not: true,
                        needle: Box::new(left),
                        haystack: Box::new(right),
                    })
                } else {
                    // not a `not in` — rewind and return left; the outer
                    // parser will see the stray `not` and either consume
                    // it as a prefix or report an error.
                    self.pos = save;
                    Ok(left)
                }
            }
            _ => Ok(left),
        }
    }

    fn parse_primary(&mut self) -> Result<Expr> {
        match self.advance() {
            Some(Token::True) => Ok(Expr::Lit(Lit::Bool(true))),
            Some(Token::False) => Ok(Expr::Lit(Lit::Bool(false))),
            Some(Token::Int(n)) => Ok(Expr::Lit(Lit::Int(n))),
            Some(Token::Str(s)) => Ok(Expr::Lit(Lit::Str(s))),
            Some(Token::LParen) => {
                let e = self.parse_expr()?;
                self.expect(Token::RParen, "`)`")?;
                Ok(e)
            }
            Some(Token::Ident(first)) => {
                // could be a function call `first(...)` or a dotted path `first.a.b`
                if matches!(self.peek(), Some(Token::LParen)) {
                    self.advance(); // (
                    let mut args = Vec::new();
                    if !matches!(self.peek(), Some(Token::RParen)) {
                        loop {
                            args.push(self.parse_expr()?);
                            if matches!(self.peek(), Some(Token::Comma)) {
                                self.advance();
                            } else {
                                break;
                            }
                        }
                    }
                    self.expect(Token::RParen, "`)`")?;
                    Ok(Expr::Call(first, args))
                } else {
                    let mut segs = vec![first];
                    while matches!(self.peek(), Some(Token::Dot)) {
                        self.advance();
                        match self.advance() {
                            Some(Token::Ident(s)) => segs.push(s),
                            _ => return self.err("expected identifier after `.`"),
                        }
                    }
                    Ok(Expr::Path(segs))
                }
            }
            Some(other) => self.err(format!("unexpected token {:?}", other)),
            None => self.err("unexpected EOF"),
        }
    }
}
