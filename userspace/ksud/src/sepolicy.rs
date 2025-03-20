use anyhow::{Result, bail};
use derive_new::new;
use nom::{
    AsChar, IResult, Parser,
    branch::alt,
    bytes::complete::{tag, take_while, take_while_m_n, take_while1},
    character::complete::{space0, space1},
    combinator::map,
};
use std::{path::Path, vec};

type SeObject<'a> = Vec<&'a str>;

fn is_sepolicy_char(c: char) -> bool {
    c.is_alphanum() || c == '_' || c == '-'
}

fn parse_single_word(input: &str) -> IResult<&str, &str> {
    take_while1(is_sepolicy_char).parse(input)
}

fn parse_bracket_objs(input: &str) -> IResult<&str, SeObject> {
    let (input, (_, words, _)) = (
        tag("{"),
        take_while_m_n(1, 100, |c: char| is_sepolicy_char(c) || c.is_whitespace()),
        tag("}"),
    )
        .parse(input)?;
    Ok((input, words.split_whitespace().collect()))
}

fn parse_single_obj(input: &str) -> IResult<&str, SeObject> {
    let (input, word) = take_while1(is_sepolicy_char).parse(input)?;
    Ok((input, vec![word]))
}

fn parse_star(input: &str) -> IResult<&str, SeObject> {
    let (input, _) = tag("*").parse(input)?;
    Ok((input, vec!["*"]))
}

// 1. a single sepolicy word
// 2. { obj1 obj2 obj3 ...}
// 3. *
fn parse_seobj(input: &str) -> IResult<&str, SeObject> {
    let (input, strs) = alt((parse_single_obj, parse_bracket_objs, parse_star)).parse(input)?;
    Ok((input, strs))
}

fn parse_seobj_no_star(input: &str) -> IResult<&str, SeObject> {
    let (input, strs) = alt((parse_single_obj, parse_bracket_objs)).parse(input)?;
    Ok((input, strs))
}

trait SeObjectParser<'a> {
    fn parse(input: &'a str) -> IResult<&'a str, Self>
    where
        Self: Sized;
}

#[derive(Debug, PartialEq, Eq, new)]
struct NormalPerm<'a> {
    op: &'a str,
    source: SeObject<'a>,
    target: SeObject<'a>,
    class: SeObject<'a>,
    perm: SeObject<'a>,
}

#[derive(Debug, PartialEq, Eq, new)]
struct XPerm<'a> {
    op: &'a str,
    source: SeObject<'a>,
    target: SeObject<'a>,
    class: SeObject<'a>,
    operation: &'a str,
    perm_set: &'a str,
}

#[derive(Debug, PartialEq, Eq, new)]
struct TypeState<'a> {
    op: &'a str,
    stype: SeObject<'a>,
}

#[derive(Debug, PartialEq, Eq, new)]
struct TypeAttr<'a> {
    stype: SeObject<'a>,
    sattr: SeObject<'a>,
}

#[derive(Debug, PartialEq, Eq, new)]
struct Type<'a> {
    name: &'a str,
    attrs: SeObject<'a>,
}

#[derive(Debug, PartialEq, Eq, new)]
struct Attr<'a> {
    name: &'a str,
}

#[derive(Debug, PartialEq, Eq, new)]
struct TypeTransition<'a> {
    source: &'a str,
    target: &'a str,
    class: &'a str,
    default_type: &'a str,
    object_name: Option<&'a str>,
}

#[derive(Debug, PartialEq, Eq, new)]
struct TypeChange<'a> {
    op: &'a str,
    source: &'a str,
    target: &'a str,
    class: &'a str,
    default_type: &'a str,
}

#[derive(Debug, PartialEq, Eq, new)]
struct GenFsCon<'a> {
    fs_name: &'a str,
    partial_path: &'a str,
    fs_context: &'a str,
}

#[derive(Debug)]
enum PolicyStatement<'a> {
    // "allow *source_type *target_type *class *perm_set"
    // "deny *source_type *target_type *class *perm_set"
    // "auditallow *source_type *target_type *class *perm_set"
    // "dontaudit *source_type *target_type *class *perm_set"
    NormalPerm(NormalPerm<'a>),

    // "allowxperm *source_type *target_type *class operation xperm_set"
    // "auditallowxperm *source_type *target_type *class operation xperm_set"
    // "dontauditxperm *source_type *target_type *class operation xperm_set"
    XPerm(XPerm<'a>),

    // "permissive ^type"
    // "enforce ^type"
    TypeState(TypeState<'a>),

    // "type type_name ^(attribute)"
    Type(Type<'a>),

    // "typeattribute ^type ^attribute"
    TypeAttr(TypeAttr<'a>),

    // "attribute ^attribute"
    Attr(Attr<'a>),

    // "type_transition source_type target_type class default_type (object_name)"
    TypeTransition(TypeTransition<'a>),

    // "type_change source_type target_type class default_type"
    // "type_member source_type target_type class default_type"
    TypeChange(TypeChange<'a>),

    // "genfscon fs_name partial_path fs_context"
    GenFsCon(GenFsCon<'a>),
}

impl<'a> SeObjectParser<'a> for NormalPerm<'a> {
    fn parse(input: &'a str) -> IResult<&'a str, Self> {
        let (input, op) = alt((
            tag("allow"),
            tag("deny"),
            tag("auditallow"),
            tag("dontaudit"),
        ))
        .parse(input)?;

        let (input, _) = space0(input)?;
        let (input, source) = parse_seobj(input)?;
        let (input, _) = space0(input)?;
        let (input, target) = parse_seobj(input)?;
        let (input, _) = space0(input)?;
        let (input, class) = parse_seobj(input)?;
        let (input, _) = space0(input)?;
        let (input, perm) = parse_seobj(input)?;
        Ok((input, NormalPerm::new(op, source, target, class, perm)))
    }
}

impl<'a> SeObjectParser<'a> for XPerm<'a> {
    fn parse(input: &'a str) -> IResult<&'a str, Self> {
        let (input, op) = alt((
            tag("allowxperm"),
            tag("auditallowxperm"),
            tag("dontauditxperm"),
        ))
        .parse(input)?;

        let (input, _) = space0(input)?;
        let (input, source) = parse_seobj(input)?;
        let (input, _) = space0(input)?;
        let (input, target) = parse_seobj(input)?;
        let (input, _) = space0(input)?;
        let (input, class) = parse_seobj(input)?;
        let (input, _) = space0(input)?;
        let (input, operation) = parse_single_word(input)?;
        let (input, _) = space0(input)?;
        let (input, perm_set) = parse_single_word(input)?;

        Ok((
            input,
            XPerm::new(op, source, target, class, operation, perm_set),
        ))
    }
}

impl<'a> SeObjectParser<'a> for TypeState<'a> {
    fn parse(input: &'a str) -> IResult<&'a str, Self> {
        let (input, op) = alt((tag("permissive"), tag("enforce"))).parse(input)?;

        let (input, _) = space1(input)?;
        let (input, stype) = parse_seobj_no_star(input)?;

        Ok((input, TypeState::new(op, stype)))
    }
}

impl<'a> SeObjectParser<'a> for Type<'a> {
    fn parse(input: &'a str) -> IResult<&'a str, Self> {
        let (input, _) = tag("type")(input)?;
        let (input, _) = space1(input)?;
        let (input, name) = parse_single_word(input)?;

        if input.is_empty() {
            return Ok((input, Type::new(name, vec!["domain"]))); // default to domain
        }

        let (input, _) = space1(input)?;
        let (input, attrs) = parse_seobj_no_star(input)?;

        Ok((input, Type::new(name, attrs)))
    }
}

impl<'a> SeObjectParser<'a> for TypeAttr<'a> {
    fn parse(input: &'a str) -> IResult<&'a str, Self> {
        let (input, _) = alt((tag("typeattribute"), tag("attradd"))).parse(input)?;
        let (input, _) = space1(input)?;
        let (input, stype) = parse_seobj_no_star(input)?;
        let (input, _) = space1(input)?;
        let (input, attr) = parse_seobj_no_star(input)?;

        Ok((input, TypeAttr::new(stype, attr)))
    }
}

impl<'a> SeObjectParser<'a> for Attr<'a> {
    fn parse(input: &'a str) -> IResult<&'a str, Self> {
        let (input, _) = tag("attribute")(input)?;
        let (input, _) = space1(input)?;
        let (input, attr) = parse_single_word(input)?;

        Ok((input, Attr::new(attr)))
    }
}

impl<'a> SeObjectParser<'a> for TypeTransition<'a> {
    fn parse(input: &'a str) -> IResult<&'a str, Self> {
        let (input, _) = alt((tag("type_transition"), tag("name_transition"))).parse(input)?;
        let (input, _) = space1(input)?;
        let (input, source) = parse_single_word(input)?;
        let (input, _) = space1(input)?;
        let (input, target) = parse_single_word(input)?;
        let (input, _) = space1(input)?;
        let (input, class) = parse_single_word(input)?;
        let (input, _) = space1(input)?;
        let (input, default) = parse_single_word(input)?;

        if input.is_empty() {
            return Ok((
                input,
                TypeTransition::new(source, target, class, default, None),
            ));
        }

        let (input, _) = space1(input)?;
        let (input, object) = parse_single_word(input)?;

        Ok((
            input,
            TypeTransition::new(source, target, class, default, Some(object)),
        ))
    }
}

impl<'a> SeObjectParser<'a> for TypeChange<'a> {
    fn parse(input: &'a str) -> IResult<&'a str, Self> {
        let (input, op) = alt((tag("type_change"), tag("type_member"))).parse(input)?;
        let (input, _) = space1(input)?;
        let (input, source) = parse_single_word(input)?;
        let (input, _) = space1(input)?;
        let (input, target) = parse_single_word(input)?;
        let (input, _) = space1(input)?;
        let (input, class) = parse_single_word(input)?;
        let (input, _) = space1(input)?;
        let (input, default) = parse_single_word(input)?;

        Ok((input, TypeChange::new(op, source, target, class, default)))
    }
}

impl<'a> SeObjectParser<'a> for GenFsCon<'a> {
    fn parse(input: &'a str) -> IResult<&'a str, Self>
    where
        Self: Sized,
    {
        let (input, _) = tag("genfscon")(input)?;
        let (input, _) = space1(input)?;
        let (input, fs) = parse_single_word(input)?;
        let (input, _) = space1(input)?;
        let (input, path) = parse_single_word(input)?;
        let (input, _) = space1(input)?;
        let (input, context) = parse_single_word(input)?;
        Ok((input, GenFsCon::new(fs, path, context)))
    }
}

impl<'a> PolicyStatement<'a> {
    fn parse(input: &'a str) -> IResult<&'a str, Self> {
        let (input, _) = space0(input)?;
        let (input, statement) = alt((
            map(NormalPerm::parse, PolicyStatement::NormalPerm),
            map(XPerm::parse, PolicyStatement::XPerm),
            map(TypeState::parse, PolicyStatement::TypeState),
            map(Type::parse, PolicyStatement::Type),
            map(TypeAttr::parse, PolicyStatement::TypeAttr),
            map(Attr::parse, PolicyStatement::Attr),
            map(TypeTransition::parse, PolicyStatement::TypeTransition),
            map(TypeChange::parse, PolicyStatement::TypeChange),
            map(GenFsCon::parse, PolicyStatement::GenFsCon),
        ))
        .parse(input)?;
        let (input, _) = space0(input)?;
        let (input, _) = take_while(|c| c == ';')(input)?;
        let (input, _) = space0(input)?;
        Ok((input, statement))
    }
}

fn parse_sepolicy<'a, 'b>(input: &'b str, strict: bool) -> Result<Vec<PolicyStatement<'a>>>
where
    'b: 'a,
{
    let mut statements = vec![];

    for line in input.split(['\n', ';']) {
        let trimmed_line = line.trim();
        if trimmed_line.is_empty() || trimmed_line.starts_with('#') {
            continue;
        }
        if let Ok((_, statement)) = PolicyStatement::parse(trimmed_line) {
            statements.push(statement);
        } else if strict {
            bail!("Failed to parse policy statement: {}", line)
        }
    }
    Ok(statements)
}

pub fn check_rule(policy: &str) -> Result<()> {
    let path = Path::new(policy);
    let policy = if path.exists() {
        std::fs::read_to_string(path)?
    } else {
        policy.to_string()
    };
    parse_sepolicy(policy.trim(), true)?;
    Ok(())
}