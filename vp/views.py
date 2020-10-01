from __future__ import unicode_literals
import csv
from datetime import datetime
import psycopg2
import ipaddress
import string, random
import re
import json

from django.shortcuts import render,redirect
from django.conf import settings

def index(request):
    return redirect("/vp/vprioritizer/dashboard")

def vulndetail(request,project_id):
    name = request.GET.get("name")
    assets = []
    conn = get_me_connection()
    print "[*] Database connected successfully"
    cur = conn.cursor()
    cur.execute("SELECT name,ip,port,cve,cvss,projected_severity,inherited_severity,description,solution,poc FROM vprioritizer_" +
                project_id + " WHERE name='" + str(name) + "'")

    for entries in cur.fetchall():
        assetelement = []
        assetelement.append(entries[1])
        assetelement.append(entries[2])
        assets.append(assetelement)
        cve = entries[3]
        cvss = entries[4]
        projected_severity = entries[5]
        inherited_severity = entries[6]
        description = entries[7]
        solution = entries[8]
        poc = entries[9]
    context = {
        "project_id": project_id,
        "name": name,
        "assets": assets,
        "cve": cve,
        "cvss": cvss,
        "projected_severity": projected_severity,
        "inherited_severity": inherited_severity,
        "description": description,
        "solution": solution,
        "poc": poc,
        "project_list": get_project_list()
    }
    return render(request, 'vuln_detail.html', context)

def asset_details(request,project_id):
    asset = request.GET.get("ip")
    vulns = []
    conn = get_me_connection()
    print "[*] Database connected successfully"
    cur = conn.cursor()
    cur.execute("SELECT name,ip,asset_criticality,cve,cvss,inherited_severity,projected_severity FROM vprioritizer_" +
                project_id + " WHERE ip='" + str(asset) + "' ORDER By cvss ASC")
    for entries in cur.fetchall():
        vulnelement = []
        vulnelement.append(entries[0])
        vulnelement.append(entries[3])
        vulnelement.append(entries[4])
        vulnelement.append(entries[5])
        vulnelement.append(entries[6])
        vulns.append(vulnelement)
        ip = entries[1]
        asset_criticality = entries[2]

    context = {
        "project_id": project_id,
        "vulns": vulns,
        "ip": ip,
        "asset_criticality": asset_criticality,
        "project_list": get_project_list()
    }
    return render(request,"asset_detail.html",context)

def triage(request,project_id):
    conn = get_me_connection()
    cur = conn.cursor()
    vulns = []

    cur.execute("SELECT id,name,cvss,ip,port,scandate,inherited_severity,projected_severity,triaged,asset_criticality from vprioritizer_"
                + project_id + " ORDER BY cvss")
    for entries in cur.fetchall():
        vulnelement = []
        for entry in entries:
            vulnelement.append(entry)
        riskstring = str(calculateseverity(entries[7],entries[3],entries[9]))
        vulnelement.append(riskstring.split("$")[0])
        vulnelement.append(riskstring.split("$")[1])
        vulns.append(vulnelement)
    context = {
        "vulns": vulns,
        "project_list": get_project_list(),
        "project_id": project_id
    }
    return render(request, 'triage.html', context)

def do_triage(request,project_id):
    id = request.POST.get("id")
    print "Updating row: " + str(id)
    conn = get_me_connection()
    print "[*] Database connected successfully"
    cur = conn.cursor()
    for vuln_asset in id.split(","):
        if vuln_asset:
            name = vuln_asset.split("#")[0]
            ip = vuln_asset.split("#")[1]
            cur.execute("UPDATE vprioritizer_" + project_id + " SET triaged = 1, projected_severity='" +
                        str(request.POST.get("severity")) +
                        "', asset_criticality='" + str(request.POST.get("asset")) +
                        "' WHERE name='" + str(name) +
                        "' AND ip='" + str(ip) + "'")
            conn.commit()
    return redirect("/vp/"+project_id+"/triage")

def update_asset(request,project_id):
    id = request.POST.get("id")
    print "Updating asset: " + str(id)
    conn = get_me_connection()
    print "[*] Database connected successfully"
    cur = conn.cursor()
    for asset in id.split(","):
        if asset:
            cur.execute("UPDATE vprioritizer_" + project_id + " SET triaged = 1, asset_criticality='" + str(
                request.POST.get("asset")) + "' WHERE ip='" + str(asset) + "'")
            conn.commit()
            print "Row " + str(asset) + " updated successfully with message " + str(cur.statusmessage)
    return redirect("/vp/" + project_id + "/asset_lookup")

def create(request):
    return redirect("/vp/" + str(request.POST.get("projectname")) + "/dashboard")

def dashboard(request,project_id):
    risklabels = []
    projectedriskdata = []
    inheritedriskdata = []
    top5vulns = []
    top5ips = []
    inherited_risk = 0
    projected_risk = 0

    try:
        conn = get_me_connection()
        print "[*] Database connected successfully"
        cur = conn.cursor()
        cur.execute("SELECT DISTINCT scandate FROM vprioritizer_" + project_id + " ORDER BY scandate ASC")

        for scandate in cur.fetchall():
            risklabels.append(str(scandate[0]))
            cur1 = conn.cursor()
            inheritedriskdatavalue = 0
            projectedriskdatavalue = 0
            cur1.execute("SELECT ip,inherited_severity,projected_severity,asset_criticality,name,asset_criticality from vprioritizer_"
                         + project_id + " WHERE scandate='" + str(scandate[0]) + "'")
            for entries in cur1.fetchall():
                currentprojectedrisk = float(calculateseverity(entries[2],entries[0],entries[3]).split("$")[0])
                inheritedriskdatavalue += float(calculateseverity(entries[1],entries[0],entries[3]).split("$")[0])
                projectedriskdatavalue += currentprojectedrisk

                try:
                    findindex = [(index, row.index(str(entries[0]))) for index, row in enumerate(top5ips) if str(entries[0]) in row]
                    top5ips[int(findindex[0][0])][1] = float(top5ips[int(findindex[0][0])][1]) + float(currentprojectedrisk)
                    print "Updated " + top5ips[int(findindex[0][0]),0]
                except Exception as ex:
                    print ex
                    top5ipelement = []
                    top5ipelement.append(entries[0])
                    top5ipelement.append(currentprojectedrisk)
                    top5ipelement.append(entries[5])
                    top5ips.append(top5ipelement)

                try:
                    findindex = [(index, row.index(str(entries[4]))) for index, row in enumerate(top5vulns) if str(entries[4]) in row]
                    top5vulns[int(findindex[0][0])][1] = float(top5vulns[int(findindex[0][0])][1]) + float(currentprojectedrisk)
                    top5vulns[int(findindex[0][0])][3] = int(top5vulns[int(findindex[0][0])][3]) + 1
                except Exception as ex:
                    top5vulnelement = []
                    top5vulnelement.append(entries[4])
                    top5vulnelement.append(currentprojectedrisk)
                    top5vulnelement.append(entries[2])
                    top5vulnelement.append(1)
                    top5vulns.append(top5vulnelement)

            top5vulns = sorted(top5vulns, key=lambda x: x[1], reverse=True)[:5]
            top5ips = sorted(top5ips, key=lambda x: x[1], reverse=True)[:5]

            inheritedriskdata.append(inheritedriskdatavalue)
            projectedriskdata.append(projectedriskdatavalue)
            inherited_risk += inheritedriskdatavalue
            projected_risk += projectedriskdatavalue
    except Exception as ex:
        print str(ex)

    context = {
        "top5vulns": top5vulns,
        "top5ips": top5ips,
        "project_id": project_id,
        "risklabels": risklabels,
        "projected_risk": projected_risk,
        "inherited_risk": inherited_risk,
        "projectedriskdata": projectedriskdata,
        "inheritedriskdata": inheritedriskdata,
        "project_list": get_project_list()
    }
    return render(request, 'dashboard.html', context)


def calculateseverity(severity,ip,asset_criticality):
    if severity is None:
        severityvalue = 0
    elif "Critical" in severity:
        severityvalue = 10
    elif "High" in severity:
        severityvalue = 8
    elif "Medium" in severity:
        severityvalue = 6
    elif "Low" in severity:
        severityvalue = 4
    else:
        severityvalue = 0

    if ipaddress.ip_address(unicode(ip)).is_private:
        accessibilityvalue = .7
    else:
        accessibilityvalue = 1.2

    if "moderate" in asset_criticality:
        asset_criticalityvalue = 1
    elif "trivial" in asset_criticality:
        asset_criticalityvalue = .5
    else:
        asset_criticalityvalue = 1.5

    return str(severityvalue * (accessibilityvalue + asset_criticalityvalue)) + "$" \
           + "severity[" + str(severityvalue) + "] * (accessibility[" \
           + str(accessibilityvalue) + "] + asset_criticality[" + str(asset_criticalityvalue) + "])"

def parse(request, project_id):
    temp_db_id = ''.join(random.choice(string.ascii_uppercase) for _ in range(32))

    print " [*] Processing " + str(request.FILES["scanfile"])
    file_reader = csv.DictReader(request.FILES["scanfile"])

    headers = file_reader.fieldnames # all headers
    table_create_string = "CREATE TABLE " + \
                          temp_db_id + \
                          " (ID BIGSERIAL PRIMARY KEY NOT NULL,"
    for head in headers:
        table_create_string = table_create_string + re.sub('[\W_]+', '_', str(head)) + " TEXT,"
    table_create_string = rreplace(table_create_string, ",", ")", 1)
    conn = get_me_connection()
    cur = conn.cursor()
    cur.execute(table_create_string)
    conn.commit()
    print "[*] Temporary database " + str(temp_db_id) + " created"
    for row in file_reader:
        insert_into_string = "INSERT INTO " + \
                             temp_db_id + \
                             " ("
        for head in headers:
            insert_into_string = insert_into_string + re.sub('[\W_]+', '_', str(head)) + ","
        insert_into_string = rreplace(insert_into_string, ",", ")", 1)
        insert_into_string = insert_into_string + " VALUES("
        for head in headers:
            if row[head] == "" or not row[head]:
                insert_into_string = insert_into_string + "NULL" + ","
            else:
                insert_into_string = insert_into_string + "'" + formatstring(str(row[head])) + "',"
        insert_into_string = rreplace(insert_into_string,",",")",1)
        cur.execute(insert_into_string)
        conn.commit()
    print "Temp table " + str(temp_db_id) + " populated successfully"

    entries = []
    mapping = get_column_mapping(temp_db_id)

    order_list = [
        'cve',
        'cvss',
        'ip',
        'hostname',
        'protocol',
        'port',
        'name',
        'description',
        'solution',
        'poc',
    ]

    select_query_string = "SELECT "
    for key in order_list:
        if mapping[key] != "None":
            select_query_string = select_query_string + mapping[key] + ","
    select_query_string = rreplace(select_query_string,",","",1)
    select_query_string = select_query_string + " FROM " + temp_db_id + " LIMIT 2"
    cur.execute(select_query_string)
    output = cur.fetchall()

    output_index = 0
    for key in order_list:
        entries_element = []
        if mapping[key] == "None":
            entries_element.append("NONE")
            entries_element.append(str(key).upper())
            entries_element.append("NONE")
            entries_element.append("NONE")
        else:
            entries_element.append(str(mapping[key]).upper())
            entries_element.append(str(key).upper())
            entries_element.append(output[0][output_index])
            entries_element.append(output[1][output_index])
            output_index = output_index + 1
        entries.append(entries_element)
    scanner = "nessus"
    context = {
        "temp_db_id": temp_db_id,
        "project_id": project_id,
        "entries": entries,
        "scanner": scanner,
        "project_list": get_project_list(),
        "columns": get_columns_list(temp_db_id)
    }
    return render(request, 'parse.html', context)

def upload(request,project_id):
    temp_db_id = request.POST.get("temp_db_id")
    scanner = request.POST.get("scanner")
    custom_mapping = json.loads(str(request.POST.get("mapping")))
    print "Custom Mapping: " + str(custom_mapping)
    conn = get_me_connection()
    cur = conn.cursor()
    if "complete" in request.POST:
        cur.execute("select exists(select * from information_schema.tables where table_name=%s)", ("vprioritizer_" + project_id,))
        if cur.fetchone()[0]:
            print "[*] Project " + project_id + " already created"
        else:
            cur.execute('''CREATE TABLE vprioritizer_''' + project_id +
                        ''' (ID BIGSERIAL PRIMARY KEY NOT NULL,
                        cve TEXT,
                        cvss FLOAT(1),
                        ip INET,
                        hostname TEXT,
                        protocol TEXT,
                        port INT,
                        name TEXT,
                        description TEXT,
                        solution TEXT,
                        poc TEXT,
                        source TEXT,
                        pocstatus TEXT DEFAULT 'pending',
                        scandate TEXT,
                        inherited_severity TEXT,
                        projected_severity TEXT,
                        triaged TEXT DEFAULT '0',
                        asset_criticality TEXT DEFAULT 'moderate');''')
            conn.commit()
            print "Project " + project_id + " created successfully"
        mapping = get_column_mapping(temp_db_id)

        order_list = [
            'cve',
            'cvss',
            'ip',
            'hostname',
            'protocol',
            'port',
            'name',
            'description',
            'solution',
            'poc',
        ]

        for (key,value) in custom_mapping.items():
            mapping[str(key).lower()] = custom_mapping[key]
        print "Final Mapping: " + str(mapping)
        select_query_string = "SELECT "
        for key in order_list:
            if mapping[key] != "None":
                select_query_string = select_query_string + mapping[key] + ","
        select_query_string = rreplace(select_query_string, ",", "", 1)
        select_query_string = select_query_string + " FROM " + temp_db_id
        cur.execute(select_query_string)
        output = cur.fetchall()
        for entry in output:
            insert_row_into_databse(entry,conn,project_id,scanner,mapping)
    print "[-] Deleting temp database " + temp_db_id
    cur.execute("DROP TABLE " + temp_db_id)
    conn.commit()
    return redirect("/vp/" + project_id + "/dashboard")

def rreplace(s, old, new, occurrence):
    li = s.rsplit(old, occurrence)
    return new.join(li)

def formatstring(str):
    return str.replace(":","-").replace("'","")

def insert_row_into_databse(row, conn, project_id,scanner,mapping):
    cur = conn.cursor()
    print row

    order_list = [
        'cve',
        'cvss',
        'ip',
        'hostname',
        'protocol',
        'port',
        'name',
        'description',
        'solution',
        'poc',
    ]

    insertintosqlquery = 'INSERT INTO vprioritizer_' \
                         + project_id + ' (' \
                         'cve,' \
                         'cvss,' \
                         'ip,' \
                         'hostname,' \
                         'protocol,' \
                         'port,' \
                         'name,' \
                         'description,' \
                         'solution,' \
                         'poc,' \
                         'source,' \
                         'scandate,' \
                         'inherited_severity,' \
                         'projected_severity)' \
                         ' VALUES ('
    # CVE -> PoC
    output_index = 0
    for key in order_list:
        if mapping[key] == "":
            insertintosqlquery = insertintosqlquery + "NULL,"
        else:
            if "port" in key:
                if "None" in str(row[output_index]) or row[output_index] is None or str(row[output_index]) == "":
                    insertintosqlquery = insertintosqlquery + "'0'" + ","
                else:
                    insertintosqlquery = insertintosqlquery + "'" + formatstring(str(row[output_index])) + "',"
            elif "cvss" in key:
                if "None" in str(row[output_index]) or row[output_index] is None or str(row[output_index]) == "":
                    insertintosqlquery = insertintosqlquery + "NULL" + ","
                else:
                    insertintosqlquery = insertintosqlquery + formatstring(str(row[output_index]).split(" ")[0]) + ","
            else:
                insertintosqlquery = insertintosqlquery + "'" + formatstring(str(row[output_index])) + "',"
            output_index = output_index + 1

    # Source
    insertintosqlquery = insertintosqlquery + "'" + scanner + "',"
    # Scan Date
    insertintosqlquery = insertintosqlquery +  "'" + datetime.now().date().strftime('%m-%d-%Y') + "',"
    # Inherited Severity
    if row[1] is None or row[1] == "":
        severity = "Informational"
    elif float(str(row[1]).split(" ")[0]) > 9:
        severity = "Critical"
    elif float(str(row[1]).split(" ")[0]) > 7:
        severity = "High"
    elif float(str(row[1]).split(" ")[0]) > 5:
        severity = "Medium"
    elif float(str(row[1]).split(" ")[0]) > 3:
        severity = "Low"
    else:
        severity = "Informational"
    insertintosqlquery = insertintosqlquery +  "'" + severity + "',"
    # Projected Severity
    try:
        cur.execute("SELECT projected_severity FROM vprioritizer_" + project_id + " WHERE name='" + row[5] + "'")
        projected_severity = cur.fetchone()[0]
        print "Updating with existing severity " + projected_severity
    except Exception as ex:
        print str(ex)
        projected_severity = severity
    insertintosqlquery = insertintosqlquery +  "'" + projected_severity + "',"
    insertintosqlquery = rreplace(insertintosqlquery, ',', ')', 1)
    cur.execute(insertintosqlquery)
    conn.commit()

def vuln_lookup(request,project_id):
    conn = get_me_connection()
    print "[*] Database connected successfully"
    cur = conn.cursor()
    cur.execute("SELECT DISTINCT name,CVSS,inherited_severity,projected_severity FROM vprioritizer_" + project_id)
    cur1 = conn.cursor()
    projected_risk = 0
    vulns = []
    id = 1
    for entries in cur.fetchall():
        vulnelement = []
        for entry in entries:
            vulnelement.append(entry)

        total = 0
        cur1.execute("SELECT projected_severity,ip,asset_criticality FROM vprioritizer_" + project_id + " WHERE name='" + str(entries[0]) + "'")
        for entries1 in cur1.fetchall():
            total = total + float(calculateseverity(entries1[0],entries1[1],entries1[2]).split("$")[0])
        projected_risk = projected_risk + total
        vulnelement.append(total)
        vulnelement.append("1")
        vulnelement.append(id)
        id = id + 1
        vulns.append(vulnelement)
    context = {
        "vulns": vulns,
        "project_id": project_id,
        "projected_risk": projected_risk,
        "project_list": get_project_list()
    }
    return render(request, 'vuln_lookup.html', context)

def update_vuln(request,project_id):
    id = request.POST.get("id")
    print "Updating vulnerability: " + str(id)
    conn = get_me_connection()
    print "[*] Database connected successfully"
    cur = conn.cursor()
    for vuln in id.split(","):
        if vuln:
            cur.execute("UPDATE vprioritizer_" + project_id + " SET triaged = 1, projected_severity='" +
                        str(request.POST.get("severity")) +
                        "' WHERE name='" + str(vuln) + "'")
            conn.commit()
            print "Row " + str(vuln) + " updated successfully with message " + str(cur.statusmessage)
    return redirect("/vp/" + project_id + "/vuln_lookup")


def asset_lookup(request,project_id):
    conn = get_me_connection()
    print "[*] Database connected successfully"
    cur = conn.cursor()
    cur.execute("SELECT DISTINCT ip,hostname,asset_criticality FROM vprioritizer_" + project_id)
    cur1 = conn.cursor()

    assets = []
    projected_risk = 0
    id = 1
    for entries in cur.fetchall():
        assetelement = []
        for entry in entries:
            assetelement.append(entry)
        assetelement.append(id)
        id = id + 1
        assetelement.append("1")

        total = 0
        cur1.execute("SELECT projected_severity,ip,asset_criticality FROM vprioritizer_" + project_id + " WHERE ip='" + str(entries[0]) + "'")
        for entries1 in cur1.fetchall():
            total = total + float(calculateseverity(entries1[0],entries1[1],entries1[2]).split("$")[0])
        projected_risk = projected_risk + total
        assetelement.append(total)
        assets.append(assetelement)
    context = {
        "assets": assets,
        "project_id": project_id,
        "projected_risk": projected_risk,
        "project_list": get_project_list()
    }
    return render(request, 'asset_lookup.html', context)

def get_me_connection():
    print settings.STATIC_URL
    conn = psycopg2.connect("dbname='" + settings.VPRIORITIZER_DATABASE['dbname'] +
                            "' user='" + settings.VPRIORITIZER_DATABASE['user'] +
                            "' host='" + settings.VPRIORITIZER_DATABASE['host'] +
                            "' password='" + settings.VPRIORITIZER_DATABASE['password'] + "'")
    print "[*] Database connected successfully"
    return conn

def get_columns_list(table_name):
    columns_list = []
    conn = get_me_connection()
    cur = conn.cursor()
    cur.execute("SELECT column_name FROM INFORMATION_SCHEMA.COLUMNS where table_name = '" + str(table_name).lower() + "';")
    output = cur.fetchall()
    for entry in output:
        columns_list.append(str(entry[0]))
    return columns_list

def get_project_list():
    project_list = []
    conn = get_me_connection()
    cur = conn.cursor()
    cur.execute("SELECT table_name FROM INFORMATION_SCHEMA.TABLES where table_schema = 'public' AND table_name LIKE 'vprioritizer_%';")
    output = cur.fetchall()
    for entry in output:
        project_list.append(str(entry[0]).replace("vprioritizer_","",1))
    return project_list

def get_column_mapping(temp_db_id):
    mapping = {
        'cve': 'None',
        'cvss': 'None',
        'ip': 'None',
        'hostname': 'None',
        'protocol': 'None',
        'port': 'None',
        'name': 'None',
        'description': 'None',
        'solution': 'None',
        'poc': 'None',
    }
    columns_list = get_columns_list(temp_db_id)
    for key in columns_list:
        if "cve" in key and "None" in mapping["cve"]:
            mapping["cve"] = key
        elif "cvss" in key and "None" in mapping["cvss"]:
            mapping["cvss"] = key
        elif ("ip" in key or "host" in key) and ("None" in mapping["ip"]):
            mapping["ip"] = key
        elif ("dns" in key or "asset_name" in key) and ("None" in mapping["hostname"]):
            mapping["hostname"] = key
        elif ("protocol" in key or "service_name" in key) and ("None" in mapping["protocol"]):
            mapping["protocol"] = key
        elif "port" in key and "None" in mapping["port"]:
            mapping["port"] = key
        elif ("title" in key or "name" in key) and ("None" in mapping["name"]):
            mapping["name"] = key
        elif ("description" in key or "threat" in key) and ("None" in mapping["description"]):
            mapping["description"] = key
        elif "solution" in key and "None" in mapping["solution"]:
            mapping["solution"] = key
        elif ("proof" in key or "output" in key or "result" in key) and "None" in mapping["poc"]:
            mapping["poc"] = key
    return mapping
