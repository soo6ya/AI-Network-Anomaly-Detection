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
        "http://127.0.0.1:8501"
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
    # STREAMLIT ENVIRONMENT
    # ========================================================

    os.environ[
        "STREAMLIT_GLOBAL_DEVELOPMENTMODE"
    ] = "false"

    os.environ[
        "STREAMLIT_SERVER_HEADLESS"
    ] = "true"

    os.environ[
        "STREAMLIT_SERVER_ADDRESS"
    ] = "127.0.0.1"

    os.environ[
        "STREAMLIT_SERVER_PORT"
    ] = "8501"

    os.environ[
        "STREAMLIT_SERVER_FILEWATCHERTYPE"
    ] = "none"

    os.environ[
        "STREAMLIT_BROWSER_SERVERADDRESS"
    ] = "127.0.0.1"

    os.environ[
        "STREAMLIT_BROWSER_SERVERPORT"
    ] = "8501"

    os.environ[
        "STREAMLIT_BROWSER_GATHERUSAGESTATS"
    ] = "false"

    # ========================================================
    # STREAMLIT CONFIGURATION
    # ========================================================

    from streamlit import config

    config.set_option(
        "server.address",
        "127.0.0.1"
    )

    config.set_option(
        "server.port",
        8501
    )

    config.set_option(
        "server.headless",
        True
    )

    config.set_option(
        "server.fileWatcherType",
        "none"
    )

    config.set_option(
        "browser.serverAddress",
        "127.0.0.1"
    )

    config.set_option(
        "browser.serverPort",
        8501
    )

    config.set_option(
        "browser.gatherUsageStats",
        False
    )

    config.set_option(
        "global.developmentMode",
        False
    )

    # ========================================================
    # STREAMLIT BOOTSTRAP
    # ========================================================

    from streamlit.web import bootstrap

    # ========================================================
    # STREAMLIT FLAGS
    # ========================================================

    flag_options = {

        "server.address":
            "127.0.0.1",

        "server.port":
            8501,

        "server.headless":
            True,

        "server.fileWatcherType":
            "none",

        "browser.serverAddress":
            "127.0.0.1",

        "browser.serverPort":
            8501,

        "browser.gatherUsageStats":
            False,

        "global.developmentMode":
            False

    }

    # ========================================================
    # LOAD STREAMLIT CONFIGURATION
    # ========================================================

    bootstrap.load_config_options(
        flag_options=flag_options
    )

    # ========================================================
    # RE-APPLY CRITICAL SETTINGS
    # ========================================================

    flag_options[
        "server.address"
    ] = "127.0.0.1"

    flag_options[
        "server.port"
    ] = 8501

    flag_options[
        "server.headless"
    ] = True

    flag_options[
        "server.fileWatcherType"
    ] = "none"

    flag_options[
        "browser.serverAddress"
    ] = "127.0.0.1"

    flag_options[
        "browser.serverPort"
    ] = 8501

    flag_options[
        "browser.gatherUsageStats"
    ] = False

    flag_options[
        "global.developmentMode"
    ] = False

    # ========================================================
    # STARTUP MESSAGE
    # ========================================================

    print(
        "Starting Network Tool..."
    )

    print()

    print(
        "Dashboard:"
    )

    print(
        "http://127.0.0.1:8501"
    )

    print()

    print(
        "Streamlit server will use port 8501."
    )

    print()

    # ========================================================
    # OPEN BROWSER
    # ========================================================

    browser_thread = threading.Thread(
        target=open_browser,
        daemon=True
    )

    browser_thread.start()

    # ========================================================
    # START STREAMLIT
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