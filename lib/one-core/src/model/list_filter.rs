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

#[derive(Clone, Debug)]
pub enum ListFilterCondition<FilterValue> {
    And(Vec<ListFilterCondition<FilterValue>>),
    Or(Vec<ListFilterCondition<FilterValue>>),
    Value(FilterValue),
}

// default implemented as an empty filter - ignored when constructing final combined query condition
impl<FilterValue> Default for ListFilterCondition<FilterValue> {
    fn default() -> Self {
        Self::And(vec![])
    }
}

// conversion from filter to simple value filter condition
pub fn into_condition<FilterValue>(filter: FilterValue) -> ListFilterCondition<FilterValue> {
    ListFilterCondition::Value(filter)
}

pub fn into_condition_opt<FilterValue>(
    filter: Option<FilterValue>,
) -> ListFilterCondition<FilterValue> {
    if let Some(filter) = filter {
        ListFilterCondition::Value(filter)
    } else {
        ListFilterCondition::default()
    }
}

// implement shorthand operators:  &, |
impl<FilterValue> std::ops::BitAnd<ListFilterCondition<FilterValue>>
    for ListFilterCondition<FilterValue>
{
    type Output = Self;
    fn bitand(self, rhs: ListFilterCondition<FilterValue>) -> Self::Output {
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

impl<FilterValue> std::ops::BitAnd<FilterValue> for ListFilterCondition<FilterValue> {
    type Output = Self;
    fn bitand(self, rhs: FilterValue) -> Self::Output {
        self & Self::Value(rhs)
    }
}

impl<FilterValue> std::ops::BitAnd<Option<ListFilterCondition<FilterValue>>>
    for ListFilterCondition<FilterValue>
{
    type Output = Self;
    fn bitand(self, rhs: Option<ListFilterCondition<FilterValue>>) -> Self::Output {
        if let Some(rhs) = rhs {
            self & rhs
        } else {
            self
        }
    }
}

impl<FilterValue> std::ops::BitAnd<Option<FilterValue>> for ListFilterCondition<FilterValue> {
    type Output = Self;
    fn bitand(self, rhs: Option<FilterValue>) -> Self::Output {
        if let Some(rhs) = rhs {
            self & rhs
        } else {
            self
        }
    }
}

impl<FilterValue> std::ops::BitOr<ListFilterCondition<FilterValue>>
    for ListFilterCondition<FilterValue>
{
    type Output = Self;
    fn bitor(self, rhs: ListFilterCondition<FilterValue>) -> Self::Output {
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

impl<FilterValue> std::ops::BitOr<FilterValue> for ListFilterCondition<FilterValue> {
    type Output = Self;
    fn bitor(self, rhs: FilterValue) -> Self::Output {
        self | Self::Value(rhs)
    }
}

impl<FilterValue> std::ops::BitOr<Option<ListFilterCondition<FilterValue>>>
    for ListFilterCondition<FilterValue>
{
    type Output = Self;
    fn bitor(self, rhs: Option<ListFilterCondition<FilterValue>>) -> Self::Output {
        if let Some(rhs) = rhs {
            self | rhs
        } else {
            self
        }
    }
}

impl<FilterValue> std::ops::BitOr<Option<FilterValue>> for ListFilterCondition<FilterValue> {
    type Output = Self;
    fn bitor(self, rhs: Option<FilterValue>) -> Self::Output {
        if let Some(rhs) = rhs {
            self | rhs
        } else {
            self
        }
    }
}
