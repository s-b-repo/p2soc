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
use gtk::prelude::*;
use std::ffi::{CString, c_void};
use std::path::Path;
use webkit2gtk::ffi as wk;
use webkit2gtk::{AuthenticationRequest, Credential, UserContentManager};

/// Optional GTK 3 system tray. StatusNotifier support is loaded at runtime
/// because an appliance without a desktop has no use for the library.
pub struct TrayIcon {
    obj: glib::Object,
    indicator: bool,
}

impl TrayIcon {
    pub fn new(menu: &gtk::Menu, show: impl Fn() + 'static) -> Option<Self> {
        if let Some(obj) = app_indicator(menu) {
            return Some(Self { obj, indicator: true });
        }
        // SAFETY: GTK is initialized on this thread and returns an owned
        // GtkStatusIcon GObject for a static NUL-terminated icon name.
        let raw = unsafe { gtk::ffi::gtk_status_icon_new_from_icon_name(c"video-display".as_ptr()) }; // audit-allow: GTK status icon has no safe wrapper, see SAFETY
        if raw.is_null() {
            return None;
        }
        // SAFETY: `raw` is a non-null, owned GtkStatusIcon, a GObject.
        let obj: glib::Object = unsafe { from_glib_full(raw.cast::<glib::gobject_ffi::GObject>()) }; // audit-allow: GTK status icon has no safe wrapper, see SAFETY
        obj.set_property("title", "SOC Wall");
        obj.set_property("tooltip-text", "SOC Wall");
        obj.set_property("visible", true);
        obj.connect_local("activate", false, move |_| {
            show();
            None
        });
        let menu = menu.clone();
        obj.connect_local("popup-menu", false, move |_| {
            menu.popup_at_pointer(None);
            None
        });
        Some(Self { obj, indicator: false })
    }

    pub fn available(&self) -> bool {
        let name = if self.indicator { "connected" } else { "embedded" };
        self.obj.find_property(name).is_some() && self.obj.property(name)
    }
}

fn app_indicator(menu: &gtk::Menu) -> Option<glib::Object> {
    type New =
        unsafe extern "C" fn(*const libc::c_char, *const libc::c_char, libc::c_int) -> *mut glib::gobject_ffi::GObject; // audit-allow: appindicator has no safe wrapper, see SAFETY below
    type SetMenu = unsafe extern "C" fn(*mut glib::gobject_ffi::GObject, *mut gtk::ffi::GtkMenu); // audit-allow: appindicator has no safe wrapper, see SAFETY below
    type SetStatus = unsafe extern "C" fn(*mut glib::gobject_ffi::GObject, libc::c_int); // audit-allow: appindicator has no safe wrapper, see SAFETY below
    for library in [c"libayatana-appindicator3.so.1", c"libappindicator3.so.1"] {
        // SAFETY: load the GTK 3 indicator ABI from a fixed system soname.
        // Do not unload successful libraries: the constructors register a GType.
        let handle = unsafe { libc::dlopen(library.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) }; // audit-allow: optional desktop library, see SAFETY
        if handle.is_null() {
            continue;
        }
        // SAFETY: `handle` is live. These are the three exported API functions
        // from app-indicator.h, cast to their matching C signatures below.
        let (ctor, set_menu, set_status) = unsafe {
            // audit-allow: optional desktop library, see SAFETY
            (
                libc::dlsym(handle, c"app_indicator_new".as_ptr()),
                libc::dlsym(handle, c"app_indicator_set_menu".as_ptr()),
                libc::dlsym(handle, c"app_indicator_set_status".as_ptr()),
            )
        };
        if ctor.is_null() || set_menu.is_null() || set_status.is_null() {
            // SAFETY: no API function was called, so this handle is unused.
            unsafe { libc::dlclose(handle) }; // audit-allow: optional desktop library, see SAFETY
            continue;
        }
        // SAFETY: dlsym returned non-null functions with the declared ABI.
        // Both strings are static and the menu is a live GtkMenu. The category
        // and status integers are APPLICATION_STATUS and ACTIVE respectively.
        let obj = unsafe {
            // audit-allow: optional desktop library, see SAFETY
            let ctor: New = std::mem::transmute(ctor); // audit-allow: matching C signature, see SAFETY above
            let set_menu: SetMenu = std::mem::transmute(set_menu); // audit-allow: matching C signature, see SAFETY above
            let set_status: SetStatus = std::mem::transmute(set_status); // audit-allow: matching C signature, see SAFETY above
            let obj = ctor(c"soc-wall".as_ptr(), c"video-display".as_ptr(), 0);
            if obj.is_null() {
                continue;
            }
            set_menu(obj, menu.to_glib_none().0);
            set_status(obj, 1);
            from_glib_full::<_, glib::Object>(obj)
        };
        return Some(obj);
    }
    None
}

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
