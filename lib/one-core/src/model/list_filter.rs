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

pub trait ListFilterValue {
    fn condition(self) -> ListFilterCondition<Self>
    where
        Self: Sized,
    {
        ListFilterCondition::Value(self)
    }
}

#[derive(Clone, Debug)]
pub enum ListFilterCondition<FV: ListFilterValue> {
    And(Vec<ListFilterCondition<FV>>),
    Or(Vec<ListFilterCondition<FV>>),
    Value(FV),
}

// default implemented as an empty filter - ignored when constructing final combined query condition
impl<FV: ListFilterValue> Default for ListFilterCondition<FV> {
    fn default() -> Self {
        Self::And(vec![])
    }
}

impl<FV: ListFilterValue> From<FV> for ListFilterCondition<FV> {
    fn from(value: FV) -> Self {
        ListFilterCondition::Value(value)
    }
}

impl<FV: ListFilterValue> From<Option<FV>> for ListFilterCondition<FV> {
    fn from(value: Option<FV>) -> Self {
        if let Some(filter) = value {
            ListFilterCondition::Value(filter)
        } else {
            ListFilterCondition::default()
        }
    }
}

// implement shorthand operators:  &, |
impl<FV: ListFilterValue> std::ops::BitAnd<ListFilterCondition<FV>> for ListFilterCondition<FV> {
    type Output = Self;
    fn bitand(self, rhs: ListFilterCondition<FV>) -> Self::Output {
        match self {
            ListFilterCondition::And(mut conditions) => match rhs {
                ListFilterCondition::And(rhs) => Self::And({
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

impl<FV: ListFilterValue> std::ops::BitAnd<FV> for ListFilterCondition<FV> {
    type Output = Self;
    fn bitand(self, rhs: FV) -> Self::Output {
        self & Self::Value(rhs)
    }
}

impl<FV: ListFilterValue> std::ops::BitAnd<Option<ListFilterCondition<FV>>>
    for ListFilterCondition<FV>
{
    type Output = Self;
    fn bitand(self, rhs: Option<ListFilterCondition<FV>>) -> Self::Output {
        if let Some(rhs) = rhs {
            self & rhs
        } else {
            self
        }
    }
}

impl<FV: ListFilterValue> std::ops::BitAnd<Option<FV>> for ListFilterCondition<FV> {
    type Output = Self;
    fn bitand(self, rhs: Option<FV>) -> Self::Output {
        if let Some(rhs) = rhs {
            self & rhs
        } else {
            self
        }
    }
}

impl<FV: ListFilterValue> std::ops::BitOr<ListFilterCondition<FV>> for ListFilterCondition<FV> {
    type Output = Self;
    fn bitor(self, rhs: ListFilterCondition<FV>) -> Self::Output {
        match self {
            ListFilterCondition::Or(mut conditions) => match rhs {
                ListFilterCondition::Or(rhs) => Self::Or({
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

impl<FV: ListFilterValue> std::ops::BitOr<FV> for ListFilterCondition<FV> {
    type Output = Self;
    fn bitor(self, rhs: FV) -> Self::Output {
        self | Self::Value(rhs)
    }
}

impl<FV: ListFilterValue> std::ops::BitOr<Option<ListFilterCondition<FV>>>
    for ListFilterCondition<FV>
{
    type Output = Self;
    fn bitor(self, rhs: Option<ListFilterCondition<FV>>) -> Self::Output {
        if let Some(rhs) = rhs {
            self | rhs
        } else {
            self
        }
    }
}

impl<FV: ListFilterValue> std::ops::BitOr<Option<FV>> for ListFilterCondition<FV> {
    type Output = Self;
    fn bitor(self, rhs: Option<FV>) -> Self::Output {
        if let Some(rhs) = rhs {
            self | rhs
        } else {
            self
        }
    }
}
