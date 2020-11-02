# This python script uses BeautifulSoup to scrape an html table from the 
# mitre website (https://cve.mitre.org/data/refs/refmap/source-EXPLOIT-DB.html') 
# and write it to a csv file as well as a DynamoDB table. 
# If you'd like to use this code to scrape an html table from a different website, 
# simply replace the url with the appropriate one, revise the manipulation of the data, 
# and write into the dataframe and DynamoDB table with the new column names.


import urllib3
import urllib.request
from bs4 import BeautifulSoup
import pandas as pd 
import csv
import os
import boto3
import json


dbTableName = os.environ['DB_TABLE_NAME']
awsRegion = os.environ['AWS_REGION']

csv_file = open('Exploit_CVE.csv', 'w')
csv_writer = csv.writer(csv_file)

# url of website we are going to get the table from
url = 'https://cve.mitre.org/data/refs/refmap/source-EXPLOIT-DB.html'

# open a connection to a URL using urllib
webUrl  = urllib.request.urlopen(url)

#get the resulting code and print it
print ("result code: " + str(webUrl.getcode()))

# read the data from the URL and print it in html form
# this is the full html, not just the table's html
# we will need to parse through this to only grab the table we are interested in
fullhtml = webUrl.read()

# use BeautifulSoup to parse through the html
soup = BeautifulSoup(fullhtml, "html.parser")

# find all the tables that fit these attributes
# we only want the ExploitDB/CVENum table, so we index with [1] to grab table #2
table = soup.findAll("table", attrs={"cellpadding":"2", "cellspacing":"2", "border":"2"})[1]

# The first tr contains the field names.
headings = ["ExploitId", "CVEId"]
datasets = []

for row in table.find_all("tr")[0:]:
    row = list(td.get_text() for td in row.find_all("td"))
    #print(type(dataset))
    #df.append(dataset, ignore_index = True)
    #df = pd.DataFrame(dataset, columns=['ExploitDB Number', 'CVE Number'])
    datasets.append(row)
    #print(dataset)

df = pd.DataFrame(datasets, columns = headings) # creating data frame with the proper headings and loading in the data
df = df.astype('string') # converting the pandas objects (default) to strings
df.drop(df.tail(2).index, inplace = True) # dropping the last two rows because they don't have exploit db Id's 
df[headings[0]] = df[headings[0]].str.replace(r'\D', '') # removing the prefix "EXPLOIT-DB" from the ExploitDBId column
df[headings[1]] = df[headings[1]].str.rstrip("\n") # removing the trailing newline from the CVEId column
df[headings[1]] = df[headings[1]].str.lstrip(' ') # removing the leading white space from the CVEId column
df[headings[1]] = df[headings[1]].str.split(' ') # splitting the column based on white space within the entries
df = df.set_index([headings[0]])[headings[1]].apply(pd.Series).stack().reset_index().drop('level_1',axis = 1).rename(columns = {0: headings[1]}) # creating multiple rows for exploits that correspond to multiple CVE #'s
print(df)
#print(df[headings[1]].nunique()) # find the number of unique CVE values

n = len(df[headings[1]]) # find the number of rows in the dataframe
csv_writer.writerow(headings)
for i in range(n - 1):
    csv_writer.writerow(df.loc[i]) # writing data frame to a csv file
        
csv_file.close()

jsonfile = df.to_json("Exploit_CVE.json", indent = 2, orient = 'records') # writing the dataframe to a json file

with open('Exploit_CVE.json', 'r') as file: # opening the json file 
    data = json.load(file)
  
dynamodb = boto3.resource('dynamodb', region_name = awsRegion)
dynamoTable = dynamodb.Table(dbTableName)

for i in data:
    dynamoTable.put_item(
            Item = {
                'CVEId' : str(i['CVEId']), # putting the json into a dictionary
                'ExploitId' : str(i['ExploitId'])
            }
    )
