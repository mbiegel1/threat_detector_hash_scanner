from flask import Flask, request, render_template, redirect, url_for
from apiarea import virusResponse
from data import Data
from file import File
from url import URL

app = Flask(__name__)

virus = virusResponse()

myFile = File()
myURL = URL()
database = Data()

min_engine_malicious_percentage = 0.25


    # another malicious hash test: 
    #   44d88612fea8a8f36de82e1278abb02f
    #   f427567a0ab47880ed224c6948af9989
    # clean hash test: f9c94a4743f2f798df2eb5728b0006baaede5534a31e0b4e26c2dedbc6c88ae5
    # hash that's below 25% detected: 0e292c9e7db321ed185c8e173bdd75f6

    # URLs:
      # Suspicious/Malicious URL: https://worldofpcgames.co/just-cause-4-free-download/
      # Suspicious/Clean URL: subtitleseeker.com
      # Clean URL: google.com
      # Malicious URL: 



# This is the base page flask calls initially with an address of "/"
# We want to route the first page to the home page
@app.route("/")
def basePage():
  print("Base Page - Initial page")
  return redirect(url_for('home'))



# This is the homepage that routes to "/home"
# It returns all the attributes that needed to be stored in the date base,
# and everything is routed to index.html but We will display them in the appropriate routes
@app.route("/home")
def home():
  print("Homepage")
  return render_template('homepage.html')



# This is the homepage that routes to "/about"
@app.route("/about")
def about():
  print("About page")
  return render_template('about.html')



# This is the homepage that routes to "/help"
@app.route("/help")
def help():
  print("Help page")
  return render_template('help.html')
  


# This is the detection page that routes to "/detection"
# Displays second page and determines whether to show a positive or negative malware page for hash
# Gets user's hash from frontend here
# Calls function to either look in database or call virusTotal to run hash
@app.route("/detection")
def Hashdetection():

  # Get size and set local variable
  size = myFile.size

  # Get total_malicious and set local variable
  total_malicious = myFile.total_malicious

  # Get total_undetected and set local variable
  total_undetected = myFile.total_undetected

  # Get md5 and set local variable
  md5 = myFile.md5_hash

  # Get sha256 and set local variable
  sha256 = myFile.sha256_hash

  # Get sha1 and set local variable
  sha1 = myFile.sha1_hash

  # Get ssdeep and set local variable
  ssdeep = myFile.ssdeep_hash

  # Get engine_data and set local variable
  engine_names = myFile.get_engines()
  engine_results = myFile.get_results()

  engine_data = make_Engine_Data(engine_names, engine_results)


  # If the number of vendors flagged as malicious is 25% or more, than the hash is considered malicious
  # Otherwise, the hash is flagged at less than 25% (indicating a CAUTION) or 0% (indicating CLEAN)
  if total_malicious/(total_malicious+total_undetected) >= min_engine_malicious_percentage:
    # file is malicious
    myFile.is_malicious = 1

    # store into database
    #database.store(myFile)

  else:
    # need to set all local vars to the File object recieve_hash returns
    myFile.is_malicious = 0
  
  is_malicious = myFile.is_malicious

  # If No vendors found the hash as malicious, return the malware_negative page
  # Else, return the malware_positive page
  if total_malicious == 0:
    return render_template('second_page_hash_malware_negative.html', **locals())
  else:
    return render_template('second_page_hash_malware_positive.html', **locals())


# This is the detection page that routes to "/detection"
# Displays second page and determines whether to show a positive or negative malware page for URL
# Gets user's URL from frontend here
# Calls function to either look in database or call virusTotal to run URL
@app.route("/detection")
def URLdetection(user_entry):

  # Get created date and set local variable
  created_date = myURL.created_date

  # Get domain name and set local variable
  domain_name = myURL.domain_name

  # Get engine result and set local variable
  engine_results = myURL.engine_results

  # Get forcepoint threatseker and set local variable
  forcepoint_threatseaker = myURL.forcepoint_threatseaker

  # Get Comodo Valkyrie's Verdict and set local variable
  comodo_verdict = myURL.comodo_valkyrie_verdict

  # Get rank of magestic and set local variable
  rank_majestic = myURL.rank_majestic

  # Get rank of statvo and set local variable
  rank_statvo = myURL.rank_statvo

  # Get registrar and set local variable
  registrar = myURL.registrar

  # Get total undetected and set local variable
  total_undetected = myURL.total_undetected

  # Get total malicious and set local variable
  total_malicious = myURL.total_malicious

  # Get engine_data and set local variable
  engine_results = myURL.get_results()
  engine_names = myURL.get_engines()

  engine_data = make_Engine_Data(engine_names, engine_results)

  # If the number of vendors flagged as malicious is 25% or more, than the hash is considered malicious
  # Otherwise, the hash is flagged at less than 25% (indicating a CAUTION) or 0% (indicating CLEAN)
  if total_malicious/(total_malicious+total_undetected) >= min_engine_malicious_percentage:

    # file is malicious
    myURL.is_malicious = 1

    # store into database
    #database.store(myFile)

  else:
    # need to set all local vars to the File object recieve_hash returns
    myURL.is_malicious = 0
  
  is_malicious = myURL.is_malicious

  # If No vendors found the hash as malicious, return the malware_negative page
  # Else, return the malware_positive page
  if total_malicious == 0:
    return render_template('second_page_URL_malware_negative.html', **locals())
  else:
    return render_template('second_page_URL_malware_positive.html', **locals())


# Displays invalid hash page for user
@app.route('/invalid_request')
def invalid_request():
  return render_template('invalid_request.html')



#@app.route('/', methods =["GET", "POST"])
@app.route('/detection', methods =["GET", "POST"])
def receive_user_entry():

  # Get the username, id, and score from front-end
  user_entry = request.form.get("uEntry")

  # Error message print statement: User's entry
  print("\n\nIn receive_user_entry function with entry:", user_entry)

  # Return True or False if user entered hash
  returnHashDetection = user_Entered_Hash(user_entry)
  print("returnHashDetection:", returnHashDetection)

  # If user entered a hash, render proper template by calling detection()
  if returnHashDetection is True:
    print("Returning Hashdetection")
    return Hashdetection()

  # Return True or False if user entered URL
  returnURLDetection = user_Entered_URL(user_entry)
  print("returnURLDetection:", returnURLDetection)

  # If user entered a URL, render proper template by calling URLdetection()
  if returnURLDetection is True:
    print("Returning URL detection")
    return URLdetection(user_entry)

  # Else, invalid response has been entered; so render invalid page via redirect to inavlid_request()
  else:
    print("NOT RETURNING DETECTION")
    return redirect(url_for('invalid_request'))



# This functions runs if the user enters a URL
# The function will search in the database first for the URL; otherwise, it will call the API
# The function will return the results of the database if the URL is in it; otherwise, it will return the API results
def user_Entered_URL(user_entry):

  user_entry = cleaning_URL_Input(user_entry)

  # Seach database for URL on user entry first
  databaseSearch = database.search_url(user_entry)

  # URL is not in database
  if databaseSearch is None:
  #   # call VT
  #   # store into database

    print("\nURL not in database, calling VirusTotal and then storing in database")
    response = virus.VT_URL_Response(user_entry)

    if (response is None or 'data' not in response):
      print("No data provided from URL; NONE")
      return False

    # Passes in what the user entered
    myURL.user_entry = user_entry
    
    # Gets file size and populates File data
    majestic_rank = get_Majestic_rank()
    myURL.rank_majestic = majestic_rank

    # Gets total malicous and populates File data
    statvo_rank = get_Statvoo_rank()
    myURL.rank_statvo = statvo_rank

    # Gets shaa256 and populates File data
    registrar = get_Registrar()
    myURL.registrar = registrar

    # Gets sha1 and populates File data
    total_malicious = get_MaliciousURL()
    myURL.total_malicious = total_malicious

    # Gets harmless and undetected values for total_undetected
    total_undetected = get_Harmless()
    total_undetected += get_UndetectedURL()
    myURL.total_undetected = total_undetected

    # Gets forcepoint threatseeker value
    forcepoint_threatseeker = get_forcepoint_threatseeker()
    myURL.forcepoint_threatseaker = forcepoint_threatseeker

    # Gets comodo valkyrie's verdict
    comodo_valkyrie_verdict = get_comodo_valkyrie_verdict()
    myURL.comodo_valkyrie_verdict = comodo_valkyrie_verdict

    # Gets creation date of site
    admin_creation_date = get_admin_creation_date()
    myURL.created_date = admin_creation_date

    # Gets domain of site
    admin_domain = get_admin_domain()
    myURL.domain_name = admin_domain

    # Gets engine results vendors and populates URL data
    engine_names, engine_results = get_URLEngine()
    myURL.set_engines(engine_names)
    myURL.set_results(engine_results)

    engine_data = make_Engine_Data(engine_names, engine_results)

    # Stores myURL data in database
    database.store_url(myURL)



  else:
  #   # no need to store, returns file object
  #   return databaseSearch
      print("URL already in database...pulling from it")

      # Grabs forcepoint threatseaker from database
      myURL.forcepoint_threatseaker = databaseSearch.forcepoint_threatseaker

      # Grabs Comodo Valkyrie Verdict from database
      myURL.comodo_valkyrie_verdict = databaseSearch.comodo_valkyrie_verdict

      # Grabs URL created date from database
      myURL.created_date = databaseSearch.created_date

      # Grabs registrar from database
      myURL.registrar = databaseSearch.registrar

      # Grabs Statvo rank from database
      myURL.rank_statvo = databaseSearch.rank_statvo

      # Grabs Majestic Rank from database
      myURL.rank_majestic = databaseSearch.rank_majestic

      # Grabs domain name from database
      myURL.domain_name = databaseSearch.domain_name

      # Grabs total_undetected from database
      myURL.total_undetected = databaseSearch.total_undetected

      # Grabs total_malicious from database
      myURL.total_malicious = databaseSearch.total_malicious


      # Grabs engines and results from database
      myURL.set_engines(databaseSearch.get_engines())
      myURL.set_results(databaseSearch.get_results())
  
  return True



# This functions runs if the user enters a hash
# The function will search in the database first for the hash; otherwise, it will call the API
# The function will return the results of the database if the hash is in it; otherwise, it will return the API results
def user_Entered_Hash(user_entry):

  # Seach database for hash
  databaseSearch = database.search_file(user_entry)

  # Hash is not in database
  if databaseSearch is None:
  #   # call VT
  #   # store into database

    print("\nHash not in database, calling VirusTotal and then storing in database")
    response = virus.VT_Hash_Response(user_entry)
    print("Got response from VT")

    if (response is None or 'data' not in response):
      print("No data provided for hash; NONE")
      return False


    # Gets file size and populates File data
    size = get_size()
    myFile.size = size

    # Gets total malicous and populates File data
    total_malicious = get_Malicious()
    myFile.total_malicious = total_malicious

    # Gets total undetected and populates File data
    total_undetected = get_Undetected()
    myFile.total_undetected = total_undetected

    # Gets md5 and populates File data
    md5 = get_md5()
    myFile.md5_hash = md5

    # Gets shaa256 and populates File data
    sha256 = get_sha256()
    myFile.sha256_hash = sha256

    # Gets sha1 and populates File data
    sha1 = get_sha1()
    myFile.sha1_hash = sha1

    # Gets ssdeep and populates File data
    ssdeep = get_ssdeep()
    myFile.ssdeep_hash = ssdeep


    # Gets engine results vendors and populates File data
    engine_names, engine_results = get_Engine()
    #print(engine_results)
    myFile.set_engines(engine_names)
    myFile.set_results(engine_results)

    engine_data = make_Engine_Data(engine_names, engine_results)

    # Stores myFile data in database
    database.store_file(myFile)

  else:
  #   # no need to store, returns file object
  #   return databaseSearch
      print("Hash already in database")

      # Gets file size and populates File data
      myFile.size = databaseSearch.size

      # Gets total malicous and populates File data
      myFile.total_malicious = databaseSearch.total_malicious

      # Gets total undetected and populates File data
      myFile.total_undetected = databaseSearch.total_undetected

      # Gets md5 and populates File data
      myFile.md5_hash = databaseSearch.md5_hash

      # Gets shaa256 and populates File data
      myFile.sha256_hash = databaseSearch.sha256_hash

      # Gets sha1 and populates File data
      myFile.sha1_hash = databaseSearch.sha1_hash

      # Gets ssdeep and populates File data
      myFile.ssdeep_hash = databaseSearch.ssdeep_hash

      # Grabs engines and results from database
      myFile.set_engines(databaseSearch.get_engines())
      myFile.set_results(databaseSearch.get_results())

    
  return True


# This functions cleans the user's input if they enter a URL
# The function will only take the main domain name to search BECAUSE 
#   VirusTotal API has the main domain names stored in their database,
#   and anything other than main domain names requires a premium API key
def cleaning_URL_Input(userInput):
  
  # Initializing variables
  cleanerInput = ""
  cleanedInput = ""
  firstDomainLetterCount = 2  # Count to get to first letter in the actual domain name

  # Break up user input based on "." to form a list
  userInput = userInput.split(".")

  # With the list, grab everything from the user's entry except
  # the leading "www", "http://www", and "https://www"
  for split in userInput:
      if (split != "www" and split != "http://www" and split != "https://www"):
          cleanerInput += split
          cleanerInput += "."

  # If there are still "https://" or "http://" in the input, remove them
  if ("https://" in cleanerInput or "http://" in cleanerInput):
      indexOfSlash = cleanerInput.index('/')+firstDomainLetterCount
      cleanerInput = cleanerInput[indexOfSlash:len(cleanerInput)]

  # Split this new "cleaner" input by slashes, and only grab
  # the first item in the list, as this is the domain name
  cleanerInput = cleanerInput.split("/")[0]

  # Remove any periods "." that may remain
  if (cleanerInput[len(cleanerInput)-1] == "."):
      cleanerInput = cleanerInput[0:len(cleanerInput)-1]

  # Set the cleaner input to the finalized returning var "cleanedInput"
  cleanedInput = cleanerInput
  print("\nCleaned URL Input: ", cleanedInput)

  return cleanedInput


# ------------------------------------------------------------------------------
# ----------------------------HASH FUNCTIONS------------------------------------
# ------------------------------------------------------------------------------

# function that gets engine all engine data for hashes
def get_Engine():
  result = virus.getHashData()
  engine = result['data']['attributes']['last_analysis_results']

  return get_Engine_Name_and_Detection_Hash(engine)


# function that gets engine all engine data for URLs
def get_URLEngine():
  result = virus.getURLData()
  engine = result['data']['attributes']['last_analysis_results']

  return get_Engine_Name_and_Detection_URL(engine)


# function that pulls out hash engine name and results from engine data
def get_Engine_Name_and_Detection_Hash(engine):

  engineNames = []
  engineResults = []

  # Get the specific engine names and results and add them to lists
  for name, results in engine.items():
    engineNames.append(name)
    engineResults.append(results['category'])

  return engineNames, engineResults


# function that pulls out URL engine name and results from engine data
def get_Engine_Name_and_Detection_URL(engine):

  engineNames = []
  engineResults = []

  # Get the specific engine names and results and add them to lists
  for name, results in engine.items():
    engineNames.append(name)
    engineResults.append(results['result'])

  return engineNames, engineResults


# function that makes engine names and data into a dictionary
def make_Engine_Data(names, detection):

  engineData = {}
  count = 0

  # Put engines names and detection in a single list
  for item in names:
    engineData[item] = detection[count]
    count +=1

  return engineData


# function that retrieve and return the size of the file
def get_size():

  result = virus.getHashData()
  d_size = result['data']['attributes']['size']

  return d_size


# function that retrieve and return the total number engines that found the file malicious
def get_Malicious():
  result = virus.getHashData()
  malicious = result['data']['attributes']['last_analysis_stats']['malicious']

  return malicious


# function that retrieve and return the md5 hash
def get_md5():
  result = virus.getHashData()
  d_md5 = result['data']['attributes']['md5']

  return d_md5


# function that retrieve and return the sha256 hash
def get_sha256():
  result = virus.getHashData()
  sha_256 = result['data']['attributes']['sha256']

  return sha_256


# function that retrieve and return the sha1 hash
def get_sha1():
  result = virus.getHashData()
  sha_1 = result['data']['attributes']['sha1']

  return sha_1


# function that retrieve and return the ssdeep hash
def get_ssdeep():
  result = virus.getHashData()
  ss_deep = result['data']['attributes']['ssdeep']

  return ss_deep


# function that retrieve and return the number of engine that did not detected any malwares on the file
def get_Undetected():
  result = virus.getHashData()
  undetected = result['data']['attributes']['last_analysis_stats']['undetected']

  return undetected



# ------------------------------------------------------------------------------
# -----------------------------URL FUNCTIONS------------------------------------
# ------------------------------------------------------------------------------


# function that retrieve and return the creation date of the domain
def get_admin_creation_date():
  
  date = ""

  result = virus.getURLData()

  try:
    admin = result['data']['attributes']['whois']

    # Gets the specific creation date from a tuple
    for item in admin.split("\n"):
      attribute = item.split(":")

      if (attribute[0] == "Creation Date"):
        date = attribute[1]

  except:
    print("Date not in VirusTotal Response")
    date = "N/A"

  return date


# function that retrieve and returns the domain name
def get_admin_domain():

  domain = ""

  result = virus.getURLData()
  try:
    admin = result['data']['attributes']['whois']

    # Gets the specific domain name from a tuple
    for item in admin.split("\n"):
      attribute = item.split(":")

      if (attribute[0] == "Domain Name"):
        domain = attribute[1]

  except:
    print("Domain not in VirusTotal Response")
    domain = "N/A"

  # set the domain to lowercase so database can pull from it properly
  domain = domain.lower()

  return domain


# function that retrieve and returns the Registrar company
def get_Registrar():
  result = virus.getURLData()
  
  try:
    registrar = result['data']['attributes']['registrar']
  except:
    print("Registrar not in VirusTotal Response")
    registrar = "N/A"

  return registrar


# function that retrieve and return Majestic's rank
def get_forcepoint_threatseeker():
  result = virus.getURLData()

  try:
    forcepoint = result['data']['attributes']['categories']['Forcepoint ThreatSeeker']
  except:
    print("Forcepoint ThreatSeeker not in VirusTotal Response")
    forcepoint = "N/A"

  return forcepoint

# function that retrieve and returns Comomdo Valkyrie's Verdict
def get_comodo_valkyrie_verdict():
  result = virus.getURLData()

  try:
    verdict = result['data']['attributes']['categories']['Comodo Valkyrie Verdict']
  except:
    print("Comodo Valkyrie Verdict not in VirusTotal Response")
    verdict = "N/A"


  return verdict


# function that retrieve and return Majestic's rank
def get_Majestic_rank():
  result = virus.getURLData()

  try:
    maj_rank = result['data']['attributes']['popularity_ranks']['Majestic']['rank']
  except:
    print("Majestic Rank not in VirusTotal Response")
    maj_rank = -1 

  return maj_rank


# function that retrieve and return Statvoo's rank
def get_Statvoo_rank():
  result = virus.getURLData()

  try:
    stat_rank = result['data']['attributes']['popularity_ranks']['Statvoo']['rank']
  except:
    print("Statvoo Rank not in VirusTotal Response")
    stat_rank = -1 
  
  return stat_rank


# function that retrieve and returns the undetected vendors
def get_UndetectedURL():
  result = virus.getURLData()
  undetected = result['data']['attributes']['last_analysis_stats']['undetected']

  return undetected


# function that retrieve and returns the harmless/clean vendors
def get_Harmless():
  result = virus.getURLData()
  harmless = result['data']['attributes']['last_analysis_stats']['harmless']

  return harmless


# function that retrieve and returns the malicious vendors
def get_MaliciousURL():
  result = virus.getURLData()
  malicious = result['data']['attributes']['last_analysis_stats']['malicious']

  return malicious
 


# main; can run app in debug mode here
if __name__ == "__main__":
    app.run(debug=True)
    #app.run(debug=False)
