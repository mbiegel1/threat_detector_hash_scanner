# Threat Detector ® Virus Scanner
# CMSC 447 Team H Submission
# Mark Biegel, Tim Yingling, Clement Onoja, Biruk Yimer, Jenna Pasternak, Scott Boyd
# Professor Allgood
# Monday/Wednesday 5:30-6:45 Section
# Contact: mbiegel1@umbc.edu
###

#### Version 1.1.0


## Objective
This application is an interactive virus hash and url scanner. Flask is used as a back-end to communicate with the Bootstrap HTML framework on the front-end. An SQL database is used to hold the data in the program via SQLite3. Features include the ability to enter hashes and URLs to be scanned, viewing the malicious status of a hash, viewing the status of the vendors for each hash or URL, and viewing hash and URL meta data. The VirusTotal API is called from the back-end to scan the entered hash and URLs and return the results of the hash or URL to be displayed to the user.


### Design
The design uses a flask back-end that displays to a Bootstrap HTML front-end and stores hash and url data in an SQLite3 database. The back-end has all functioanlity to get the required properties (sha256, md5, sha1, etc...) from the database or API to display to the user. The VirusTotal API is called to get the results if the hash or URL has never been scanned before; otherwise, the results are pulled from the database. The back-end passes the results to the front-end to display to the user in an easy-to-read format.


### Files
There are siz python files, one database file, three extra files, and two folders:
    <br>`app.py`: Contains the back-end to communicate between HTML and the SQL database
    <br>`apiarea.py`: Contains API calls to VirusTotal and data manipulation for formatting
    <br>`data.py`: Contains functionality for pulling and pushing data to and from the SQL database.
    <br>`data_test.py`: Tests database functionality
    <br>`file.py`: Class for object oriented programming in order to interact and get hash from database
    <br>`proj_data.db`: Database file that stores hash and URL data and is accessed by application during use
    <br>`url.py`: Class for object oriented programming in order to interact and get URL from database
    <br>`requirements.txt`: Holds the dependencies needed for Threat Detector®; uses `pip install` to install them
    <br>`threatdetector_app.sh`: Main executable to run Threat Detector®
    <br>`threatdetector_app_backup.sh`: Backup executable to run Threat Detector®
    <br>
    <br>`templates/`: Contains all HTML templates that are used and displayed on each respected page:
        <br>`homepage.html`: Interface output for the home screen of the application
        <br>`invalid_request.html`: Interface output for an invalid request from user
        <br>`second_page__hash_malware_negative.html`: Interface and page if malware is not detected in the hash.
        <br>`second_page__hash_malware_positive.html`: Interface and page if malware is detected in the hash.
        <br>`second_page__URL_malware_negative.html`: Interface and page if malware is not detected in the URL.
        <br>`second_page__URL_malware_positive.html`: Interface and page if malware is detected in the URL.
        <br>`about.html`: Interface and page for verison and description information about Threat Detector®.
        <br>`help.html`: Interface and page for user to seek help about how to use the Threat Detector® site.
    <br>
    <br>`static/`: Contains `.css` sheets as well as `.svg`, `.jpg`, `.png`, and `.gif` graphics.
        <br>`about.css`: style sheet for the about page
        <br>`checkmark.gif`: GIF checkmark symbol for the NEGATVIE status (when a user's entry is not flgged at all)
        <br>`help.css`: style sheet for the help page
        <br>`homepage_img.jpg`: JPEG image displayed on homepage
        <br>`homepage.css`: style sheet used in `homepage.html`
        <br>`no_data.gif`: GIF used when invalid request is entered on `invalid_request.html`
        <br>`no_data.png`: Back-up image for `invalid_request.html` if GIF fails
        <br>`secondpage.css` style sheet for the second page where all malicious information is displayed.
        <br>`x-mark.png`: PNG caution symbol for the POSITIVE status (when a user's entry is 25% or more flagged)



### Assumptions
It is assumed you have a Linux environment with `git` installed as well as a basic understanding of using Linux. A `requirements.txt` is provided and is run by the `threatdetector_app.sh` executable. A virtual environment is not needed, but recommended. Now, you can clone the repo into a directory. Then proceed to the `Running the application` section in this `README.md`.

*NOTE: This application has been tested on Linux only; operating distribution commands varies.
Use linux for the best experience!*


### Running the application
Clone the repo with the following command: `git clone git@github.com:cmsc447-sp2022/teamH.git`. After cloning the repo, change to the directory `teamH` with the command `cd teamH` folder and switch to the `release branch` with the command: `git checkout release`. If you want to download a `.zip` folder of the repo, download from the `release` branch and unzip the folder. You should now see files called `threatdetector_app.sh` and `threatdetector_app_backup.sh`. We will make thse executables now with the following commands:
    <br>`chmod u+x threatdetector_app.sh`
    <br>`chmod u+x threatdetector_app_backup.sh`
<br>After making both executables, enter the following command to run the application: `./threatdetector_app.sh`

This installs `pip3` if it is not already installed as well as the necessary dependencies to run the application and then runs the application.
<br>Once the application starts, Flask outputs information into the terminal, giving you an address to enter into your browser to view the website.
The address should be: `http://127.0.0.1:5000/`; however, given the unpredicatbility of computers, it may be different
for some odd reason, so check the output, specifically where it says `"Running on...."` to see the address. Open that link.

*NOTE: If the `threatdetector_app.sh` does not work, and you are unable to launch the application, try running `./threatdetector_app_backup.sh`.
This executable creates an environment, install Flask and necessary dependencies, and run the application. This executable
has only been tested on Linux systems*

Then, proceed to the `Using the application` section in this `README.md`.


### Using the application
Opening up the link directs you to the homepage. Here, there is a search box to enter hashes and URLs to be scanned. Also there is an `ABOUT` button which describes information about Threat Detector ®. There is also a `HELP` button that includes a description about how to use the website and all the features. 

Entering a hash or URL redirects to a page that displays determining if the hash or URL is malicious or not. The page shows 3 tabs: number of vendors that flagged the hash/URL as malicious, metadata of the hash/URL, and the status of the hash/URL being malicious or not:
    <br><br> `Detection` Tab: Shows the number of vendors which either have a check mark indicating that the vendor flagged the hash/URL as clean (not malicious), an "X" mark indicating the vendor flagged it as malicious, and a "?" indicating the vendor cannot the file type.
    <br><br> `Metadata` Tab: Shows relevant statistics and information pertain to the user's entry. The statistics for a hash are different compared to the statistics for a URL.
    <br><br> `Malicious Status` Tab: Shows a graphic based on the resulting malicious status
The top of the page has a navigation bar where a new hash/URL can be entered for ease of use; no need to redirect to the homepage. Furthermore, the navigation bar has the program name and logo; clicking either of these redirects to the homepage.

Entering an invalid hash or URL results in a page that states an invalid request has been made. It gives a button that, when clicked,redirects back to the home page.

*NOTE* If you want to stop the program, use `Ctrl+C` to end the application and not `Ctrl+Z`. `Ctrl+Z` seems to not allow the program to 
run correctly if you were to relaunch the server and run the application again. If you do hit `Ctrl+Z` to stop the program, the solution 
that works for me is to close the terminal and relaunch a new one, navigate to the folder, and run the executable again.
