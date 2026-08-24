import os
import sys
import time
import threading
import webbrowser

# ============================================================
# EXPLICIT IMPORTS FOR PYINSTALLER
# ============================================================

import streamlit
import pandas
import numpy
import sklearn
import joblib
import scapy
import winotify


# ============================================================
# GET APPLICATION DIRECTORY
# ============================================================

def get_base_directory():

    if getattr(sys, "frozen", False):
        return sys._MEIPASS

    return os.path.dirname(
        os.path.abspath(__file__)
    )


# ============================================================
# OPEN BROWSER
# ============================================================

def open_browser():

    time.sleep(5)

    webbrowser.open(
        "http://localhost:8501"
    )


# ============================================================
# MAIN
# ============================================================

def main():

    base_directory = get_base_directory()

    dashboard_path = os.path.join(
        base_directory,
        "dashboard.py"
    )

    print("=" * 60)
    print("NETWORK TOOL")
    print("=" * 60)
    print()

    print(
        f"Application directory: {base_directory}"
    )

    print(
        f"Dashboard: {dashboard_path}"
    )

    print()

    # ========================================================
    # CHECK DASHBOARD
    # ========================================================

    if not os.path.isfile(dashboard_path):

        print(
            "ERROR: dashboard.py was not found."
        )

        print(
            f"Expected location: {dashboard_path}"
        )

        input(
            "Press Enter to exit..."
        )

        return

    # ========================================================
    # WORKING DIRECTORY
    # ========================================================

    os.chdir(
        base_directory
    )

    # ========================================================
    # STREAMLIT CONFIGURATION
    # ========================================================

    os.environ[
        "STREAMLIT_GLOBAL_DEVELOPMENTMODE"
    ] = "false"

    os.environ[
        "STREAMLIT_SERVER_HEADLESS"
    ] = "true"

    os.environ[
        "STREAMLIT_SERVER_ADDRESS"
    ] = "localhost"

    os.environ[
        "STREAMLIT_SERVER_PORT"
    ] = "8501"

    os.environ[
        "STREAMLIT_SERVER_FILEWATCHERTYPE"
    ] = "none"

    os.environ[
        "STREAMLIT_BROWSER_GATHERUSAGESTATS"
    ] = "false"

    # ========================================================
    # IMPORT STREAMLIT BOOTSTRAP
    # ========================================================

    from streamlit.web import bootstrap

    # ========================================================
    # OPEN BROWSER
    # ========================================================

    browser_thread = threading.Thread(
        target=open_browser,
        daemon=True
    )

    browser_thread.start()

    # ========================================================
    # STREAMLIT FLAGS
    # ========================================================

    flag_options = {

        "server.address":
            "localhost",

        "server.port":
            8501,

        "server.headless":
            True,

        "server.fileWatcherType":
            "none",

        "browser.gatherUsageStats":
            False,

        "global.developmentMode":
            False

    }

    print(
        "Starting Network Tool..."
    )

    print(
        "Dashboard:"
    )

    print(
        "http://localhost:8501"
    )

    print()

    # ========================================================
    # START STREAMLIT
    #
    # The second argument is False.
    # This prevents Streamlit from interpreting the
    # command-line string as the is_hello parameter.
    # ========================================================

    bootstrap.run(

        dashboard_path,

        False,

        [],

        flag_options

    )


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":

    main()