import re
def html(sample):
    output = "<link rel='stylesheet' href='style.css'>"
    output += "<body>"
    output += "<ul id='navbar'>"
    output += "<li><a href='#info'>Info</a></li>"

    output += "<li><a href='#suspicious'>Automa Highlights</a></li>"

    try:
        if sample.peinfo:
            output += "<li><a href='#pefile'>PEFile</a></li>"
    except AttributeError:
        pass
    try:
        if sample.floss:
            output += "<li><a href='#floss'>FLOSS</a></li>"
    except AttributeError:
        pass
    try:
        if sample.capa:
            output += "<li><a href='#capa'>Capa</a></li>"
    except AttributeError:
        pass

    try:
        if sample.capaunpacked:
            output += "<li><a href='#capaunpacked'>Capa Unpacked</a></li>"
    except AttributeError:
        pass

    try:
        if sample.virustotal:
            output += "<li><a href='#virustotal'>VirusTotal</a></li>"
    except AttributeError:
        pass

    try:
        if sample.inetsim:
            output += "<li><a href='#inetsim'>INetSim</a></li>"
    except AttributeError:
        pass

    try:
        if sample.pesieve:
            output += "<li><a href='#pesieve'>PE-Sieve</a></li>"
    except AttributeError:
        pass

    try:
        if sample.ramscan or sample.cmdcheck:
            output += "<li><a href='#volatility'>Volatility</a></li>"
    except AttributeError:
        pass







    
       
    output += "</ul>"
    output += "<div id='content'>"
    output += "<h1 id='info'>" + sample.name + "</h1>\n"
    output +="<table><tr><th>Filename</th><td>" + sample.name + "</td></tr>"
    output += "<tr><th>MD5</th><td>" + sample.md5 + "</td></tr>"
    output += "<tr><th>ImpHash</th><td>" + sample.imphash + "</td></tr>"
    output += "<tr><th>VirusTotal</th><td><a href='https://www.virustotal.com/gui/file/" + sample.md5 + "'>Detection</a></td></tr>"
    output += "</table>"

    if sample.malware:
        output += "<h4 id='suspicious'>Here are some items that Automa found to be suspicious:</h4>"
        output += "<table>"
        for reason in sample.reasons:
            output += "<tr><td>" + reason + "</td><td>"
            output += "<ul>"

            for evidence in sample.reasons[reason]:
                output += "<li>" + evidence + "</li>"
            output += "</ul></td></tr>"
        output += "</table>"
    else:
        output += "<h4 id='suspicious'>Automa failed to find any suspicious items in the sample. However, refer to the results below for a better idea of the sample</h4>"
    
    try:
        if sample.peinfo:
            output += "<h2 id='pefile'>PEFile</h2>"

            data = re.split('\n-', sample.peinfo)

            for section in data:
                lines = section.split('\n')

                output += "<button onclick=\"reveal('" + lines[0].replace(' ', '').replace('-','') + "')\">" + lines[0].replace('-', '') + "</button><br>"
                output += "<p id='" + lines[0].replace(' ', '').replace('-','') + "' style='display:none;'>" 
                for line in lines[2:-1]:
                    output += line + "<br>"
                output += "</p>"
            output += "<script>function reveal(id) { var x = document.getElementById(id); if (x.style.display === 'none') { x.style.display = 'block'; } else { x.style.display = 'none'; }}</script>"
    except AttributeError:
        pass

    try:
        if sample.floss:
            output += "<h2 id='floss'>FLOSS Results</h2>"
            for key in sample.floss["strings"]:
                output += "<h4>" + key.replace("_", " ").title() + "</h4>"
                #if key == "decoded_strings":
#
 #                   output += "<ul id='floss'>"
  #                  for string in sample.floss["strings"][key]:
   #                     output += "<li>" + string + "</li>"
    #                output += "</ul>"

                if sample.floss["strings"][key]:
                    output += "<ul>"
                    for string in sample.floss["strings"][key]:
                        #Replaces less than symbol with html entity as was causing bug that was creating unclosed comments
                        output += "<li>" + string.replace("<", "&lt") + "</li>"
                    output += "</ul>"
                else:
                    output += "<p>FLOSS found 0 " + key.replace("_", " ") + "</p>"
    except AttributeError:
        pass

    try:
        if sample.capa:
            output += "<h2 id='capa'>FireEye's Capa</h2>"
        if sample.capa["rules"]:
            output += "<p>Here are the capabilities capa found: </p>"
            output += "<ul>"
            for key in sample.capa["rules"]:
                output += "<li>" + key + "</li>"
            output += "</ul>"
                
        else:
            output += "<p>Capa found 0 capabilities in this sample. This could be because it is safe or the file successfully hid its functionality using tools like packers</p>"
        output += "<p>Manually run Capa on the sample if more detailed is required</p>"
    except AttributeError:
        pass

    try: 
        if sample.capaunpacked:
            output += "<h2 id='capaunpacked'>Unpacked with Unipacker and Capa</h2>"

        if sample.capaunpacked["rules"]:
           output += "<p>Here are the capabilities capa found on the attempted unpack: </p>"
           output += "<ul>"
           for key in sample.capaunpacked["rules"]:
               output+= "<li>" + key + "</li>"
           output += "</ul>"     
        else: 
            output += "<p>Capa found 0 capabilities in the unpacked version of the sample.</p>"
    except AttributeError:
        pass

    try:
        if sample.virustotal:
            output += "<h2 id='virustotal'>VirusTotal Results</h2>"
            output += "<table>"
            for key in sample.virustotal:
                output += "<tr>"
                if sample.virustotal[key]["result"]:
                    output += "<th>" + key + "</th><td>" + sample.virustotal[key]["category"] + "</td><td>" + sample.virustotal[key]["result"] + "</td>"
                else:

                    output += "<th>" + key + "</th><td>" + sample.virustotal[key]["category"] + "</td>"
                output += "</tr>"
            output += "</table>"
            output += "The detection rate is: " + str(len(sample.reasons["VirusTotal"])) + "/" + str(len(sample.virustotal))
    except AttributeError:
        pass
    except KeyError:
        pass

    try:
        if sample.inetsimpid:
            output += inetsimformat(sample.inetsimpid)
    except AttributeError:
        pass

    try:
        if sample.pesieve:
            output += "<h2 id='pesieve'>PE-Sieve</h2>"
            output += "<p>PE-Sieve scanned a total of " + str(sample.pesieve["scanned"]["total"]) + " modules</p>"
            
            output += "<table>"
            for item in sample.pesieve["scanned"]["modified"]:
                output += "<tr><th>" + item.replace("_", " ") + "</th><td>" + str(sample.pesieve["scanned"]["modified"][item]) + "</td></tr>"
            output += "</table>"
             
    except AttributeError:
        pass

    try: 
        if sample.ramscan or sample.cmdcheck:
            output += "<h2 id='volatility'>Volatility</h2>"
            if sample.ramscan:
                output += "<h3>Plugin: Ramscan</h3>"
                output += "<table><tr>"
                for column in sample.ramscan["columns"]:
                    output += "<th>" + column + "</th>"
                output += "</tr>"

                for row in sample.ramscan["rows"]:
                    output += "<tr>"
                    for item in row:
                        output += "<td>" + str(item) + "</td>"
                    output += "</tr>"
                output += "</table>"

            if sample.cmdcheck:
                output += "<h3>Plugin: CMDCheck</h3>"
                output += "<table><tr>"
                for column in sample.cmdcheck["columns"]:
                    output += "<th>" + column + "</th>"
                output += "</tr>"

                for row in sample.cmdcheck["rows"]:
                    output += "<tr>"
                    for item in row:
                        output += "<td>" + str(item) + "</td>"
                    output += "</tr>"
                output += "</table>"
    except AttributeError:
        pass
    
    #javascript
    #output += "<script>"
    #output += "var ul = document.getElementById('floss');\n"
    #output += "ul.addEventListener('click', function(e) { if (e.target.tagName === 'LI') { alert(e.target.id); }});"
    #output += "</script>"


    return output

def inetsimformat(pid):
    try:
        #INetSim report is made as root so needs permission changes
        os.system("sudo chmod 444 /home/debian/Desktop/honours/inetsim/report." + str(pid) + ".txt > /dev/null")

        output = "<h3 id='inetsim'>INetSim</h3>"
        with open("/home/debian/Desktop/honours/inetsim/report." + str(pid) + ".txt") as f:
            for line in f.readlines():
                output += "<pre>" + line + "</pre>"
        return output
    except:
        return ""
        
 
