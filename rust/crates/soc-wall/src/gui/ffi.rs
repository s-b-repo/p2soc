//! The few C calls the safe GTK/WebKit bindings do not expose.
//!
//! * Compiled tracker content filters: WebKit can block requests inside its
//!   network process from a compiled rule list (`WebKitUserContentFilter`) —
//!   far cheaper and tighter than observing loads from the host.
//! * Answering an HTTP authentication challenge with a credential.
//! * Per-window `WM_CLASS`, which X11 window managers place windows by.
//!
//! This is the only FFI in the GUI; everything unsafe is confined to this
//! file and each block states the invariant it relies on.
#![allow(unsafe_code)] // audit-allow: irreducible FFI — gtk-rs exposes no safe wrapper, see SAFETY

use glib::translate::{ToGlibPtr, ToGlibPtrMut, from_glib_full};
use std::ffi::{CString, c_void};
use std::path::Path;
use webkit2gtk::ffi as wk;
use webkit2gtk::{AuthenticationRequest, Credential, UserContentManager};

/// A compiled rule list, reference-counted by WebKit.
pub struct Filter(std::ptr::NonNull<wk::WebKitUserContentFilter>);

impl Filter {
    /// Install the filter on a content manager (WebKit takes its own
    /// reference).
    pub fn add_to(&self, ucm: &UserContentManager) {
        let manager: *mut wk::WebKitUserContentManager = ucm.to_glib_none().0;
        // SAFETY: `manager` is a live WebKitUserContentManager borrowed from
        // `ucm` for the duration of the call, and `self.0` is a filter we hold
        // a reference to.
        unsafe { wk::webkit_user_content_manager_add_filter(manager, self.0.as_ptr()) } // audit-allow: irreducible FFI — gtk-rs exposes no safe wrapper, see SAFETY
    }
}

impl Clone for Filter {
    fn clone(&self) -> Filter {
        // SAFETY: `self.0` is valid while `self` lives; ref returns the same
        // non-null pointer with its count raised.
        unsafe { wk::webkit_user_content_filter_ref(self.0.as_ptr()) }; // audit-allow: irreducible FFI — gtk-rs exposes no safe wrapper, see SAFETY
        Filter(self.0)
    }
}

impl Drop for Filter {
    fn drop(&mut self) {
        // SAFETY: we own exactly one reference, taken at construction/clone.
        unsafe { wk::webkit_user_content_filter_unref(self.0.as_ptr()) } // audit-allow: irreducible FFI — gtk-rs exposes no safe wrapper, see SAFETY
    }
}

/// On-disk store of compiled filters.
pub struct FilterStore(glib::Object);

type SaveOutcome = Result<Filter, String>; // audit-allow: String is the human-facing reason/display text
type SaveCallback = Box<dyn FnOnce(SaveOutcome)>;

impl FilterStore {
    /// Open (creating if needed) the store under `dir`. `None` when the path
    /// cannot be handed to WebKit.
    pub fn new(dir: &Path) -> Option<FilterStore> {
        let path = CString::new(dir.to_str()?).ok()?;
        // SAFETY: `path` is a valid NUL-terminated string for the call; the
        // constructor returns a new GObject whose single reference we adopt.
        let raw = unsafe { wk::webkit_user_content_filter_store_new(path.as_ptr()) }; // audit-allow: irreducible FFI — gtk-rs exposes no safe wrapper, see SAFETY
        if raw.is_null() {
            return None;
        }
        // SAFETY: `raw` is a non-null, owned WebKitUserContentFilterStore,
        // which is a GObject.
        Some(FilterStore(unsafe { from_glib_full(raw.cast::<glib::gobject_ffi::GObject>()) })) // audit-allow: irreducible FFI — gtk-rs exposes no safe wrapper, see SAFETY
    }

    fn raw(&self) -> *mut wk::WebKitUserContentFilterStore {
        let obj: *mut glib::gobject_ffi::GObject = self.0.to_glib_none().0;
        obj.cast()
    }

    /// Compile `rules_json` (WebKit content-blocker JSON) under `identifier`
    /// and call `done` on the main loop with the result. Must be called on
    /// the GTK main thread.
    pub fn save(&self, identifier: &str, rules_json: &str, done: impl FnOnce(SaveOutcome) + 'static) {
        let Ok(ident) = CString::new(identifier) else {
            done(Err("filter identifier contains a NUL byte".into()));
            return;
        };
        let source = glib::Bytes::from(rules_json.as_bytes());
        let callback: SaveCallback = Box::new(done);
        let user_data = Box::into_raw(Box::new(callback)).cast::<c_void>();
        // SAFETY: the store, identifier and bytes are valid for the call
        // (WebKit copies/refs what it keeps). `user_data` is a leaked
        // Box<SaveCallback> that `save_done` reclaims exactly once: GIO
        // guarantees the ready callback runs exactly once.
        #[rustfmt::skip]
        let () = unsafe { // audit-allow: irreducible FFI — gtk-rs exposes no safe wrapper, see SAFETY
            wk::webkit_user_content_filter_store_save(
                self.raw(),
                ident.as_ptr(),
                source.to_glib_none().0,
                std::ptr::null_mut(),
                Some(save_done),
                user_data,
            )
        };
    }
}

#[rustfmt::skip]
unsafe extern "C" fn save_done( // audit-allow: irreducible FFI — gtk-rs exposes no safe wrapper, see SAFETY
    source: *mut glib::gobject_ffi::GObject,
    result: *mut gio::ffi::GAsyncResult,
    user_data: *mut c_void,
) {
    // SAFETY: `user_data` is the Box<SaveCallback> leaked by `save`, handed
    // back exactly once.
    let callback: Box<SaveCallback> = unsafe { Box::from_raw(user_data.cast()) }; // audit-allow: irreducible FFI — gtk-rs exposes no safe wrapper, see SAFETY
    let mut error: *mut glib::ffi::GError = std::ptr::null_mut();
    // SAFETY: `source` is the store the operation was started on and `result`
    // the matching async result, both valid for this callback; `error` is a
    // valid out-pointer.
    let raw = unsafe { wk::webkit_user_content_filter_store_save_finish(source.cast(), result, &mut error) }; // audit-allow: irreducible FFI — gtk-rs exposes no safe wrapper, see SAFETY
    let outcome = match std::ptr::NonNull::new(raw) {
        Some(filter) => Ok(Filter(filter)),
        None if error.is_null() => Err("filter compilation failed".to_string()),
        None => {
            // SAFETY: a non-null GError out-value is owned by us.
            let err: glib::Error = unsafe { from_glib_full(error) }; // audit-allow: irreducible FFI — gtk-rs exposes no safe wrapper, see SAFETY
            Err(err.to_string())
        }
    };
    // A panic must not unwind into C.
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| callback(outcome))); // audit-allow: best-effort, a panicking callback must not unwind across the C boundary
}

/// Answer an authentication challenge with `credential`.
pub fn authenticate(request: &AuthenticationRequest, credential: &mut Credential) {
    let request: *mut wk::WebKitAuthenticationRequest = request.to_glib_none().0;
    // SAFETY: both pointers are borrowed from live wrappers for the duration
    // of the call; WebKit copies the credential (transfer none).
    unsafe { wk::webkit_authentication_request_authenticate(request, credential.to_glib_none_mut().0) } // audit-allow: irreducible FFI — gtk-rs exposes no safe wrapper, see SAFETY
}

/// Set a window's X11 `WM_CLASS` (name and class). Must be called before the
/// window is realized; it is a no-op on Wayland.
pub fn set_wmclass(window: &gtk::Window, class: &str) {
    let Ok(class) = CString::new(class) else {
        return;
    };
    let window: *mut gtk::ffi::GtkWindow = window.to_glib_none().0;
    // SAFETY: `window` is a live GtkWindow borrowed for the call and `class`
    // a valid NUL-terminated string that GTK copies.
    unsafe { gtk::ffi::gtk_window_set_wmclass(window, class.as_ptr(), class.as_ptr()) } // audit-allow: irreducible FFI — gtk-rs exposes no safe wrapper, see SAFETY
}
