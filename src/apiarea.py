'''
This lines are comments.
After copying the API request function from Virus Total, the file was modified.
1 - We import json, and the reason for that was to load the response in json format. 
2 - We can set parameter if we want an only the attributes with the set parameter will be displayed.

'''
# Imports
import requests
import json


# Globabl list for hash data
Hashdata_list = []
Hashdata_list.append(None)

# Global list for URL data
URLdata_list = []
URLdata_list.append(None)

# ----------------------------------
# Class for calling VirusTotal API
# ----------------------------------
class virusResponse:

  # Function returns data for hash
  def getHashData(arbitraryArgumentThatIsNotUsed):
    return Hashdata_list[0]


  # Function returns data for URL
  def getURLData(arbitraryArgumentThatIsNotUsed):
    return URLdata_list[0]


  # Function calls VirusTotal on hash
  def VT_Hash_Response(self, userHashFunction=None):

    # If the the user's entry is not passed into this method, an error has occurred
    if userHashFunction is None:
      print("\nAn error has occurred: Unable to pass hash function to VirusTotal API")
      return None

    # Else if the user's entry is empty, then nothing will happen (prompted in terminal)    
    elif userHashFunction == "":
      print("\nUSER: YOU MUST ENTER SOMTHING INTO THE SEARCH BAR")

    # Else, the user's entry is passed to VirusTotal
    else:
      print("\nCalling VirusTotal on user's hash function:", userHashFunction)
      url = "https://www.virustotal.com/api/v3/files/" + userHashFunction

      headers = {
        "Accept": "application/json",

        # Clement's API Key: c749820807d2bef533708564acb0c49d970f2263b6633f99e04cc3a53c9cd7c8
        # Mark's API Key: 4ea24321e6e93aa4e19a1732d6348ed0bc67310ee85efe91e316d8072fba65c4
        "x-apikey": "4ea24321e6e93aa4e19a1732d6348ed0bc67310ee85efe91e316d8072fba65c4"
        
      }

      # Get response from VirusTotal
      response = requests.request("GET", url, headers=headers)

      # Load data into global variable
      data = json.loads(response.text)
      Hashdata_list[0] = data

      return data

  # Function calls VirusTotal on URL
  def VT_URL_Response(self, userURL=None):
      
      # If the the user's entry is not passed into this method, an error has occurred
      if userURL is None:
        print("\nAn error has occurred: Unable to pass URL function to VirusTotal API")
        return None
      
      # Else if the user's entry is empty, then nothing will happen (prompted in terminal)
      elif userURL == "":
        print("\nUSER: YOU MUST ENTER SOMTHING INTO THE SEARCH BAR")

      # Else, the user's entry is passed to VirusTotal
      else:
        print("\nCalling VirusTotal on user's URL:", userURL)
        url = "https://www.virustotal.com/api/v3/domains/" + userURL

        headers = {
          "Accept": "application/json",

          # Clement's API Key: c749820807d2bef533708564acb0c49d970f2263b6633f99e04cc3a53c9cd7c8
          # Mark's API Key: 4ea24321e6e93aa4e19a1732d6348ed0bc67310ee85efe91e316d8072fba65c4
          "x-apikey": "c749820807d2bef533708564acb0c49d970f2263b6633f99e04cc3a53c9cd7c8"
          
        }
        
        # Get response from VirusTotal
        response = requests.request("GET", url, headers=headers)

        # Load data into global variable
        data = json.loads(response.text)
        URLdata_list[0] = data

        return data





