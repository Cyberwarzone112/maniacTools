from datetime import date 
#custom options
##usage 
#python decode_ps.py >> report.html
#tool via https://cyberwarzone.com

###
target_shortname = "Powershell attack" 
author = "Cyberwarzone"
email = "https://cyberwarzone.com"
classification = "classified"



def give_target_file(): 
    original_file_raw = r"""
    PLACE THE POWERSHELL SCRIPT HERE
    """
    return original_file_raw


def returnbase64(stringx):
    import base64
    base64_message = stringx
    base64_bytes = base64_message.encode('ascii')
    message_bytes = base64.b64decode(base64_bytes)
    message = message_bytes.decode('ascii') 
    return message
     

def create_draft_report(objectss,base64strings,comobject,webrequestss,requests_methodss,iterators):  
    today = date.today() 
    # dd/mm/YY
    d1 = today.strftime("%d/%m/%Y") 
    header_draft = "<p><center><h1>Cyberwarzone.com quick powershell checker v1</h1></center></p>"
    header_subtitle = "<p><h2>" + target_shortname + "</h2></p>"
    ##table
    table = ("""        <center>        <table style="border-collapse: collapse; width: 100%; height: 90px;" border="1">        <tbody>        <tr style="height: 18px;">        <td style="width: 50%; height: 18px;"><strong>Author</strong></td>        <td style="width: 50%; height: 18px;">[author]</td>        </tr>        <tr style="height: 18px;">        <td style="width: 50%; height: 18px;"><strong>Contact</strong></td>        <td style="width: 50%; height: 18px;">[contact]</td>        </tr>        <tr style="height: 18px;">        <td style="width: 50%; height: 18px;"><strong>Date</strong></td>        <td style="width: 50%; height: 18px;">[date]</td>        </tr>        <tr style="height: 18px;">        <td style="width: 50%; height: 18px;"><strong>Classification</strong></td>        <td style="width: 50%; height: 18px;">[classification]</td>        </tr>        </tbody>        </table>        </center>""")
    table = table.replace("[author]",author)
    table = table.replace("[contact]",email)
    table = table.replace("[date]",d1)
    table = table.replace("[classification]",classification)
    iocs = "<p><h1>Network IOC</h1></p><p>We have found " + str(len(webrequestss)) + " network indicators." 
    story = header_draft + header_subtitle + table + iocs
    for n in webrequestss:
        story = story +  "<li>" + str(webrequestss[n]) + '\t' + n + "</li>"

    base64s = "<p><h1>Base64 encoded strings</h1></p><p>We have found " + str(len(base64strings)) + " base64 strings."    
    story = story + base64s
    for nn in base64strings:
        story = story +  "<li>" + str(base64strings[nn]) + '\t' + returnbase64(nn) + '\t' + nn + "</li>"
       
    print(story)
    print("<h1>Not finished yet</h1>")
    print("<h1>definitions</h1>")
    print(objectss)
    print("<h1>com objects</h1>")
    print(comobject)
    print("<h1>Request methods</h1>")
    print(requests_methodss)
    print("<h1>Most likely an iterator</h1>")
    print(iterators)




def start_extracting_info(target_file):
    cache = target_file
    objectss = {}
    base64strings = {}
    comobject = {}
    webrequestss = {}
    requests_methodss = {}
    iterators = {}
    for xxx in cache.split('\n'): 
        investigation_line = xxx 
        investigation_line = investigation_line.lower()
        
        if '{' in investigation_line:
            cachedx = investigation_line.split('{')
            for b in cachedx:
                if '}' in b:
                    partion = b.split('}')[0]
                    full = "{" + partion + "}"
                    if full in objectss:
                        objectss[full] = objectss[full] + 1
                    if full not in objectss:
                        objectss[full] = 1
        if "FromBase64String('" in xxx:
            basex = xxx.split("FromBase64String('")[1].split("'")[0]
            if basex in base64strings:
                base64strings[basex] = base64strings[basex] + 1
            if basex not in base64strings:
                base64strings[basex] = 1
        if 'new-object -comobject' in investigation_line: 
            obx = investigation_line.split('new-object -comobject')[1].strip() 
            if obx in comobject:
                comobject[obx] = comobject[obx] + 1
            if obx not in comobject:
                comobject[obx] = 1    
        if '[system.net.webrequest]::create' in investigation_line:
            requests_web = investigation_line.split("[system.net.webrequest]::create")[1]
            requests_web = requests_web.split("(")[1]
            requests_web = requests_web.split(")")[0]
            
            if requests_web in webrequestss:
                webrequestss[requests_web] = webrequestss[requests_web] + 1
            if requests_web not in webrequestss:
                webrequestss[requests_web] = 1    
        if '://' in investigation_line: 
            if investigation_line in webrequestss:
                webrequestss[investigation_line] = webrequestss[investigation_line] + 1
            if investigation_line not in webrequestss:
                webrequestss[investigation_line] = 1    
        if 'WebRequest.Method' in xxx:
            requests_method = xxx.split("WebRequest.Method")[1]
            requests_method = requests_method.split("=")[1].strip() 
            if requests_method in requests_methodss:
                requests_methodss[requests_method] = requests_methodss[requests_method] + 1
            if requests_method not in requests_methodss:
                requests_methodss[requests_method] = 1 

        ##iterator detect
        if "for("  in investigation_line:
            if '=' in investigation_line.split('for(')[1]:
                checklist = ["++,",".count"]
                found = 0
                for x in checklist:
                    if x in investigation_line:
                        found = found + 1
                if found != 0: 
                    if xxx in iterators:
                        iterators[xxx] = iterators[xxx] + 1
                    if xxx not in iterators:
                        iterators[xxx] = 1 
    
    #print(objectss)
    #print(base64strings)
    #print(comobject)
    #print(requests_methodss)
    #print(iterators)
    create_draft_report(objectss,base64strings,comobject,webrequestss,requests_methodss,iterators)





     

start_extracting_info(give_target_file())
        