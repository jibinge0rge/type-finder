import os
import importlib.util
import sys

import streamlit as st

st.set_page_config(layout="wide")

def _load_loader_type_validation_module():
    """Dynamically load the module defined in 'loader-type-validation.py'."""
    base_dir = os.path.dirname(os.path.abspath(__file__))
    module_path = os.path.join(base_dir, "loader-type-validation.py")

    if not os.path.isfile(module_path):
        raise FileNotFoundError(f"Could not find 'loader-type-validation.py' at {module_path}")

    spec = importlib.util.spec_from_file_location("loader_type_validation", module_path)
    module = importlib.util.module_from_spec(spec)
    assert spec is not None and spec.loader is not None
    try:
        spec.loader.exec_module(module)
    except ModuleNotFoundError as exc:
        # Provide minimal stubs for optional dependencies used only in CLI paths
        missing_name = getattr(exc, 'name', '') or str(exc).split("'")[1]
        if missing_name in ('swifter', 'tqdm'):
            if missing_name == 'swifter':
                class _SwifterStub:
                    def __getattr__(self, name):
                        raise AttributeError("'swifter' is not available in this environment")

                sys.modules['swifter'] = _SwifterStub()  # type: ignore
            elif missing_name == 'tqdm':
                class _TqdmModuleStub:
                    class tqdm:  # mimic 'from tqdm import tqdm'
                        def __init__(self, *args, **kwargs):
                            pass
                        def __enter__(self):
                            return self
                        def __exit__(self, exc_type, exc, tb):
                            return False
                        def set_postfix(self, **kwargs):
                            pass
                        def update(self, n=1):
                            pass

                sys.modules['tqdm'] = _TqdmModuleStub()  # type: ignore

            spec.loader.exec_module(module)
        else:
            raise
    return module


def run_get_new_type_tester():
    """Streamlit UI to manually test a single input against get_new_type()."""
    st.title("Type Finder")
    st.caption("This uses the exact function from 'loader-type-validation.py' via dynamic import.")

    with st.form("get_new_type_form"):
        internal_contributor = st.text_input("internal_contributor", value="")
        host_name = st.text_input("host_name", value="")

        cloud_native_type_text = st.text_input(
            "cloud_native_type", value=""
        )

        submitted = st.form_submit_button("Evaluate")

    if submitted:
        module = _load_loader_type_validation_module()
        get_new_type = getattr(module, "get_new_type", None)
        if get_new_type is None:
            st.error("Could not find get_new_type in loader-type-validation.py")
            return

        row = {
            "internal_contributor": internal_contributor if internal_contributor != "" else None,
            "host_name": host_name if host_name != "" else None,
            "cloud_native_type": cloud_native_type_text if cloud_native_type_text != "" else None,
        }

        try:
            new_type = get_new_type(row)
        except Exception as exc:
            st.exception(exc)
            return

        st.success(f"new_type = {new_type}")
        with st.expander("Input row passed to get_new_type"):
            st.json(row)


if __name__ == "__main__":
    run_get_new_type_tester()


