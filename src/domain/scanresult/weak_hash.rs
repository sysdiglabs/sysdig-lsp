use std::hash::{Hash, Hasher};
use std::sync::Weak;

/// A wrapper for `Weak<T>` that implements `Hash`, `PartialEq`, and `Eq`
/// based on the pointer address of the underlying data. This allows `Weak<T>`
/// pointers to be stored in collections like `HashSet`.
pub struct WeakHash<T: ?Sized>(pub Weak<T>);

impl<T: ?Sized> Clone for WeakHash<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T: ?Sized> Hash for WeakHash<T> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.as_ptr().hash(state);
    }
}

impl<T: ?Sized> PartialEq for WeakHash<T> {
    fn eq(&self, other: &Self) -> bool {
        self.0.ptr_eq(&other.0)
    }
}

impl<T: ?Sized> Eq for WeakHash<T> {}
