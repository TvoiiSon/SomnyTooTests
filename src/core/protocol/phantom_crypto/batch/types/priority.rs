#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BatchPriority {
    Low,
    Normal,
    High,
    Immediate,
}