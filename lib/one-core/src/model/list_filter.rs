#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StringMatchType {
    Equals,
    StartsWith,
    EndsWith,
    Contains,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StringMatch {
    pub r#match: StringMatchType,
    pub value: String,
}

impl StringMatch {
    pub fn equals(value: impl Into<String>) -> Self {
        Self {
            r#match: StringMatchType::Equals,
            value: value.into(),
        }
    }

    pub fn starts_with(value: impl Into<String>) -> Self {
        Self {
            r#match: StringMatchType::StartsWith,
            value: value.into(),
        }
    }

    pub fn ends_with(value: impl Into<String>) -> Self {
        Self {
            r#match: StringMatchType::EndsWith,
            value: value.into(),
        }
    }

    pub fn contains(value: impl Into<String>) -> Self {
        Self {
            r#match: StringMatchType::Contains,
            value: value.into(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ComparisonType {
    Equal,
    NotEqual,
    LessThan,
    GreaterThan,
    LessThanOrEqual,
    GreaterThanOrEqual,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValueComparison<Value> {
    pub comparison: ComparisonType,
    pub value: Value,
}

pub trait ListFilterValue {
    fn condition(self) -> ListFilterCondition<Self>
    where
        Self: Sized,
    {
        ListFilterCondition::Value(self)
    }
}

#[derive(Clone, Debug)]
pub enum ListFilterCondition<FV> {
    And(Vec<ListFilterCondition<FV>>),
    Or(Vec<ListFilterCondition<FV>>),
    Value(FV),
}

// default implemented as an empty filter - ignored when constructing final combined query condition
impl<FV> Default for ListFilterCondition<FV> {
    fn default() -> Self {
        Self::And(vec![])
    }
}

impl<FV> From<FV> for ListFilterCondition<FV> {
    fn from(value: FV) -> Self {
        ListFilterCondition::Value(value)
    }
}

impl<FV> From<Option<FV>> for ListFilterCondition<FV> {
    fn from(value: Option<FV>) -> Self {
        if let Some(filter) = value {
            ListFilterCondition::Value(filter)
        } else {
            ListFilterCondition::default()
        }
    }
}

// implement shorthand operators:  &, |
impl<FV> std::ops::BitAnd<ListFilterCondition<FV>> for ListFilterCondition<FV> {
    type Output = Self;
    fn bitand(self, rhs: ListFilterCondition<FV>) -> Self::Output {
        match self {
            Self::And(mut conditions) => match rhs {
                Self::And(rhs) => Self::And({
                    conditions.extend(rhs);
                    conditions
                }),
                rhs => Self::And({
                    conditions.push(rhs);
                    conditions
                }),
            },
            _ => Self::And(vec![self, rhs]),
        }
    }
}

impl<FV> std::ops::BitAnd<FV> for ListFilterCondition<FV> {
    type Output = Self;
    fn bitand(self, rhs: FV) -> Self::Output {
        self & Self::Value(rhs)
    }
}

impl<FV> std::ops::BitAnd<Option<ListFilterCondition<FV>>> for ListFilterCondition<FV> {
    type Output = Self;
    fn bitand(self, rhs: Option<ListFilterCondition<FV>>) -> Self::Output {
        if let Some(rhs) = rhs {
            self & rhs
        } else {
            self
        }
    }
}

impl<FV> std::ops::BitAnd<Option<FV>> for ListFilterCondition<FV> {
    type Output = Self;
    fn bitand(self, rhs: Option<FV>) -> Self::Output {
        if let Some(rhs) = rhs {
            self & rhs
        } else {
            self
        }
    }
}

impl<FV> std::ops::BitOr<ListFilterCondition<FV>> for ListFilterCondition<FV> {
    type Output = Self;
    fn bitor(self, rhs: ListFilterCondition<FV>) -> Self::Output {
        match self {
            Self::Or(mut conditions) => match rhs {
                Self::Or(rhs) => Self::Or({
                    conditions.extend(rhs);
                    conditions
                }),
                rhs => Self::Or({
                    conditions.push(rhs);
                    conditions
                }),
            },
            _ => Self::Or(vec![self, rhs]),
        }
    }
}

impl<FV> std::ops::BitOr<FV> for ListFilterCondition<FV> {
    type Output = Self;
    fn bitor(self, rhs: FV) -> Self::Output {
        self | Self::Value(rhs)
    }
}

impl<FV> std::ops::BitOr<Option<ListFilterCondition<FV>>> for ListFilterCondition<FV> {
    type Output = Self;
    fn bitor(self, rhs: Option<ListFilterCondition<FV>>) -> Self::Output {
        if let Some(rhs) = rhs {
            self | rhs
        } else {
            self
        }
    }
}

impl<FV> std::ops::BitOr<Option<FV>> for ListFilterCondition<FV> {
    type Output = Self;
    fn bitor(self, rhs: Option<FV>) -> Self::Output {
        if let Some(rhs) = rhs {
            self | rhs
        } else {
            self
        }
    }
}

impl<FV> ListFilterCondition<FV> {
    pub fn is_empty(&self) -> bool {
        match self {
            Self::And(conditions) | Self::Or(conditions) => conditions.is_empty(),
            Self::Value { .. } => false,
        }
    }

    /// Tests if any node of the condition contains a specific filter value
    /// - visits all nodes until the `matcher` gives a positive result
    pub fn contains<Matcher: Fn(&FV) -> bool>(&self, matcher: &Matcher) -> bool {
        match self {
            Self::And(conditions) | Self::Or(conditions) => conditions
                .iter()
                .any(|condition| condition.contains(matcher)),
            Self::Value(fv) => matcher(fv),
        }
    }
}
