import couchdb #download and install couchdb via the official documentation
#template by https://cyberwarzone.com

serverlocation = 'http://username:password@destip:port/'
def sendtocouchdb(document):
    DATABASENAME = "mydatabase" #the human readable name of your database (in this db the data will be stored)
    couch = couchdb.Server(serverlocation)
    documentID = "" #we make a holder for the documentID
    try:
        
        db = couch[DATABASENAME]
        doc = document
        db.save
        documentID = db.save(doc)
        
    except Exception as e: 
        print(e)
    return documentID #returns the document id

sampledoc = {"document_name":{"data":{"name":"cyberwarzone","details":"cyberwarzone.com"}}}
sendtocouchdb(sampledoc)