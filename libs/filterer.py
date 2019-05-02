import re

def ip_equal(url, ip=None):
    if not ip:
        return re.search(r'^(https?:\/\/)?\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d{1,5})?(\/.*)?$', url)
    elif ip == 'lan':
        return re.search(r'^(https?:\/\/)?((127\.\d{1,3}\.\d{1,3}\.\d{1,3})|(192\.168\.\d{1,3}\.\d{1,3})|(10\.\d{1,3}\.\d{1,3}\.\d{1,3})|(172\.1[6-9]\.\d{1,3}\.\d{1,3})|(172\.2[0-9]\.\d{1,3}\.\d{1,3})|(172\.3[0-1]\.\d{1,3}\.\d{1,3}))(:\d{1,5})?(\/.*)?$', url)
    else:
        return re.search(r'^(https?:\/\/)?('+ ip.replace(',','|') +')(:\d{1,5})?(\/.*)?$', url)

def tld_equal(url, tld):
    return re.search(r'^(https?:\/\/)?(\w*\.)*(' + tld.replace(',','|') + ')(\/.*)?$', url)

def domain_equal(url, domain):
    return re.search(r'^(https?:\/\/)?(.*\.)?('+ domain.replace(',','|') +')(:\d{1,5})?(\/.*)?$', url)

def protocol_equal(url, protocol):
    return re.search(r'^'+ protocol.replace(',','|') +':\/\/.*', url)

def filetype_equal(url, filetype):
    return re.search(r'^https?:\/\/.*\/.*\.('+ filetype.replace(',','|') +')$', url)

def port_equal(url, port):
    return re.search(r'^https?:\/\/.*:('+ port.replace(',','|') +')\/.*.$', url)

def is_wordpress(url):
    return re.search(r'(wp-login\.php|\/wp-content\/|\/wp-admin)', url)

def is_adminpanel(url):
    return re.search(r'(\/admin\/|\/administrator\/|\/wp-admin)', url)

def is_localfile(url):
    return re.search(r'file:\/\/', url)

def is_xss_attack(url):
    return re.search(r'''<[^\w<>]*(?:[^<>"'\s]*:)?[^\w<>]*(?:\W*s\W*c\W*r\W*i\W*p\W*t|\W*f\W*o\W*r\W*m|\W*s\W*t\W*y\W*l\W*e|\W*s\W*v\W*g|\W*m\W*a\W*r\W*q\W*u\W*e\W*e|(?:\W*l\W*i\W*n\W*k|\W*o\W*b\W*j\W*e\W*c\W*t|\W*e\W*m\W*b\W*e\W*d|\W*a\W*p\W*p\W*l\W*e\W*t|\W*p\W*a\W*r\W*a\W*m|\W*i?\W*f\W*r\W*a\W*m\W*e|\W*b\W*a\W*s\W*e|\W*b\W*o\W*d\W*y|\W*m\W*e\W*t\W*a|\W*i\W*m\W*a?\W*g\W*e?|\W*v\W*i\W*d\W*e\W*o|\W*a\W*u\W*d\W*i\W*o|\W*b\W*i\W*n\W*d\W*i\W*n\W*g\W*s|\W*s\W*e\W*t|\W*i\W*s\W*i\W*n\W*d\W*e\W*x|\W*a\W*n\W*i\W*m\W*a\W*t\W*e)[^>\w])|(?:<\w[\s\S]*[\s\0\/]|['"])(?:formaction|style|background|src|lowsrc|ping|on(?:d(?:e(?:vice(?:(?:orienta|mo)tion|proximity|found|light)|livery(?:success|error)|activate)|r(?:ag(?:e(?:n(?:ter|d)|xit)|(?:gestur|leav)e|start|drop|over)?|op)|i(?:s(?:c(?:hargingtimechange|onnect(?:ing|ed))|abled)|aling)|ata(?:setc(?:omplete|hanged)|(?:availabl|chang)e|error)|urationchange|ownloading|blclick)|Moz(?:M(?:agnifyGesture(?:Update|Start)?|ouse(?:PixelScroll|Hittest))|S(?:wipeGesture(?:Update|Start|End)?|crolledAreaChanged)|(?:(?:Press)?TapGestur|BeforeResiz)e|EdgeUI(?:C(?:omplet|ancel)|Start)ed|RotateGesture(?:Update|Start)?|A(?:udioAvailable|fterPaint))|c(?:o(?:m(?:p(?:osition(?:update|start|end)|lete)|mand(?:update)?)|n(?:t(?:rolselect|extmenu)|nect(?:ing|ed))|py)|a(?:(?:llschang|ch)ed|nplay(?:through)?|rdstatechange)|h(?:(?:arging(?:time)?ch)?ange|ecking)|(?:fstate|ell)change|u(?:echange|t)|l(?:ick|ose))|m(?:o(?:z(?:pointerlock(?:change|error)|(?:orientation|time)change|fullscreen(?:change|error)|network(?:down|up)load)|use(?:(?:lea|mo)ve|o(?:ver|ut)|enter|wheel|down|up)|ve(?:start|end)?)|essage|ark)|s(?:t(?:a(?:t(?:uschanged|echange)|lled|rt)|k(?:sessione|comma)nd|op)|e(?:ek(?:complete|ing|ed)|(?:lec(?:tstar)?)?t|n(?:ding|t))|u(?:ccess|spend|bmit)|peech(?:start|end)|ound(?:start|end)|croll|how)|b(?:e(?:for(?:e(?:(?:scriptexecu|activa)te|u(?:nload|pdate)|p(?:aste|rint)|c(?:opy|ut)|editfocus)|deactivate)|gin(?:Event)?)|oun(?:dary|ce)|l(?:ocked|ur)|roadcast|usy)|a(?:n(?:imation(?:iteration|start|end)|tennastatechange)|fter(?:(?:scriptexecu|upda)te|print)|udio(?:process|start|end)|d(?:apteradded|dtrack)|ctivate|lerting|bort)|DOM(?:Node(?:Inserted(?:IntoDocument)?|Removed(?:FromDocument)?)|(?:CharacterData|Subtree)Modified|A(?:ttrModified|ctivate)|Focus(?:Out|In)|MouseScroll)|r(?:e(?:s(?:u(?:m(?:ing|e)|lt)|ize|et)|adystatechange|pea(?:tEven)?t|movetrack|trieving|ceived)|ow(?:s(?:inserted|delete)|e(?:nter|xit))|atechange)|p(?:op(?:up(?:hid(?:den|ing)|show(?:ing|n))|state)|a(?:ge(?:hide|show)|(?:st|us)e|int)|ro(?:pertychange|gress)|lay(?:ing)?)|t(?:ouch(?:(?:lea|mo)ve|en(?:ter|d)|cancel|start)|ime(?:update|out)|ransitionend|ext)|u(?:s(?:erproximity|sdreceived)|p(?:gradeneeded|dateready)|n(?:derflow|load))|f(?:o(?:rm(?:change|input)|cus(?:out|in)?)|i(?:lterchange|nish)|ailed)|l(?:o(?:ad(?:e(?:d(?:meta)?data|nd)|start)?|secapture)|evelchange|y)|g(?:amepad(?:(?:dis)?connected|button(?:down|up)|axismove)|et)|e(?:n(?:d(?:Event|ed)?|abled|ter)|rror(?:update)?|mptied|xit)|i(?:cc(?:cardlockerror|infochange)|n(?:coming|valid|put))|o(?:(?:(?:ff|n)lin|bsolet)e|verflow(?:changed)?|pen)|SVG(?:(?:Unl|L)oad|Resize|Scroll|Abort|Error|Zoom)|h(?:e(?:adphoneschange|l[dp])|ashchange|olding)|v(?:o(?:lum|ic)e|ersion)change|w(?:a(?:it|rn)ing|heel)|key(?:press|down|up)|(?:AppComman|Loa)d|no(?:update|match)|Request|zoom))[\s\0]*=''', url, re.IGNORECASE)

def is_sqli_attack(url):
    return re.search(r'''(?:(union(.*)select(.*)from))|(?:[\s()]case\s*\()|(?:\)\s*like\s*\()|(?:if\s?\([\d\w]\s*[=<>~])|(?:\"\s*or\s*\"?\d)|(?:\\x(?:23|27|3d))|(?:^.?\"$)|(?:(?:^[\"\\]*(?:[\d\"]+|[^\"]+\"))+\s*(?:n?and|x?or|not|\|\||\&\&)\s*[\w\"[+&!@(),.-])|(?:[^\w\s]\w+\s*[|-]\s*\"\s*\w)|(?:@\w+\s+(and|or)\s*[\"\d]+)|(?:@[\w-]+\s(and|or)\s*[^\w\s])|(?:[^\w\s:]\s*\d\W+[^\w\s]\s*\".)|(?:\Winformation_schema|table_name\W)|(?:\"\s*\*.+(?:or|id)\W*\"\d)|(?:\^\")|(?:^[\w\s\"-]+(?<=and\s)(?<=or\s)(?<=xor\s)(?<=nand\s)(?<=not\s)(?<=\|\|)(?<=\&\&)\w+\()|(?:\"\s*[^\w\s]+\s*[\W\d].*(?:--))|(?:\".*\*\s*\d)|(?:\"\s*or\s[^\d]+[\w-]+.*\d)|(?:[\d\W]\s+as\s*[\"\w]+\s*from)|(?:^[\W\d]+\s*(?:union|select|create|rename|truncate|load|alter|delete|update|insert|desc))|(?:(?:select|create|rename|truncate|load|alter|delete|update|insert|desc)\s+(?:(?:group_)concat|char|load_file)\s?\(?)|(?:end\s*\);)|(\"\s+regexp\W)|(?:[\s(]load_file\s*\()|(?:@.+=\s*\(\s*select)|(?:\d+\s*or\s*\d+\s*[\-+])|(?:\/\w+;?\s+(?:having|and|or|select)\W)|(?:\d\s+group\s+by.+\()|(?:(?:;|--)\s*(?:drop|alter))|(?:(?:;|--)\s*(?:update|insert)\s*\w{2,})|(?:[^\w]SET\s*@\w+)|(?:(?:n?and|x?or|not |\|\||\&\&)[\s(]+\w+[\s)]*[!=+]+[\s\d]*[\"=()])|(?:\"\s+and\s*=\W)|(?:\(\s*select\s*\w+\s*\()|(?:\*\/from)|(?:\+\s*\d+\s*\+\s*@)|(?:\w\"\s*(?:[-+=|@]+\s*)+[\d(])|(?:coalesce\s*\(\w+\s*[^\w\s])|(?:\W!+\"\w)|(?:\";\s*(?:if|while|begin))|(?:\"[\s\d]+=\s*\d)|(?:order\s+by\s+if\w*\s*\()|(?:[\s(]+case\d*\W.+[tw]hen[\s(])''', url, re.IGNORECASE)

def is_lfi_attack(url):
    return re.search(r'''(?:etc\/\W*passwd)|(?:(?:\/|\\)?\.\.+(\/|\\)(?:\.+)?)''', url, re.IGNORECASE)

def is_social(url):
    return re.search(r'''http(s)?:\/\/(.*\.)?youtube.com\/[A-z0-9_-]+\/?|http(s)?:\/\/(.*\.)?twitter\.com\/[A-z0-9_]+\/?|http(s)?:\/\/([\w]+\.)?linkedin\.com\/in\/[A-z0-9_-]+\/?|http(s)?:\/\/([\w]+\.)?linkedin\.com\/pub\/[A-z0-9_-]+(\/[A-z0-9]+){3}\/?|http(s)?:\/\/(www\.)?(facebook|fb)\.com\/[A-z0-9_\-\.]+\/?|https?:\/\/(www\.)?instagram\.com\/([A-Za-z0-9_](?:(?:[A-Za-z0-9_]|(?:\.(?!\.))){0,28}(?:[A-Za-z0-9_]))?)|https?:\/\/plus\.google\.com\/\+[^\/]+|\d{21}|(?:(?:callto|skype):)(?:[a-z][a-z0-9\\.,\\-_]{5,31})(?:\\?(?:add|call|chat|sendfile|userinfo))?|https?:\/\/(t(elegram)?\.me|telegram\.org)\/([a-z0-9\_]{5,32})\/?''', url, re.IGNORECASE)

def is_technical(url):
    return re.search(r'''http(s)?:\/\/(www\.)?exploit-db.com\/exploits\/?\d{1,6}|http(s)?:\/\/(.*\.)?technet.microsoft.com\/[A-z0-9_-]+\/?|http(s)?:\/\/(.*\.)?stackexchange.com\/[A-z0-9_-]+\/?|http(s)?:\/\/(www\.)?stackoverflow.com\/[A-z0-9_-]+\/?|http(s)?:\/\/(www\.)?github\.com\/[A-z0-9_-]+\/?|http(s)?:\/\/([A-z0-9-_]+)\.github\.(com|io)\/?''', url, re.IGNORECASE)

def is_storage(url):
    return re.search(r'''http(s)?:\/\/(www\.)?drive.google.com\/drive\/folders\/.*|http(s)?:\/\/(www\.)?dropbox.com\/s\/|http(s)?:\/\/(www\.)?mega.nz\/#.*|http(s)?:\/\/(www\.)?wetransfer.com\/.*|http(s)?:\/\/(www\.)?transferxl.com\/.*|http(s)?:\/\/(www\.)?icloud.com\/.*''', url, re.IGNORECASE)
