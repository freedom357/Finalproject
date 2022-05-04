from ast import Or
from ntpath import join
from elasticsearch import Elasticsearch
from django import template
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse, HttpResponseRedirect
from django.template import loader
from django.urls import reverse
from datetime import datetime, timedelta, timezone
from dateutil import tz
import pytz
import pprint
from django.shortcuts import render, redirect
from django.http import HttpResponse
import csv
from apps.home import views
# from django.shortcuts import render, redirect


@login_required(login_url="/login/")

def index(request):
    # Tables
    query_body_table = {
        "from": 0,
        "size": 10,
        "sort": [
            {
            "@timestamp": {
                "order": "desc"
            }
            }
        ],
        "query": {
            "query_string": {
            "query": "@timestamp: [now-1d TO now] AND enriched.misp.threat_indicator.feed: misp"
            }
        }
    }
    # Graph 1
    query_body_traffic = {
        "size": 0, 
        "query": {
            "range": {
            "@timestamp": {
                "gte": "now-1d",
                "lte": "now"
            }
            }
        },
        "aggs": {
            "timeline": {
            "date_histogram": {
                "field": "@timestamp",
                "interval": "hour"
            }
            }
        }
    }
    #Graph2
    query_body_match = {
        "size": 0,
        "query": {
            "range": {
            "@timestamp": {
                "gte": "now-1M",
                "lte": "now"
                }
                }
            },
        "aggs": {
            "timeline": {
            "date_histogram": {
                "field": "@timestamp",
                "interval": "day"
            }
            }
        }
    }
    #Graph3
    query_body_misp = {
    "size": 0,
    "query": {
        "query_string": {
        "query": "@timestamp: [now-1d TO now] AND enriched.misp.threat_indicator.feed: misp"
        }
    },
    "aggs": {
        "timeline": {
        "date_histogram": {
            "field": "@timestamp",
            "interval": "hour"
        }
        }
    }
    }
    index_table = 'filebeat-udp*'
    index_traffic = 'filebeat-udp*'
    index_match = 'filebeat-httpjson-*'
    index_misp = 'filebeat-udp*'
# connect index_traffic================================================================================
    client_traffic = Elasticsearch('http://192.168.1.77:9200', http_auth=('elastic', 'isylzjkoD3v'))
    es_traffic = client_traffic.search(index=index_traffic,  body=query_body_traffic, filter_path=['aggregations.timeline.*'])
    # print('*'* 99)
    # print(es_traffic)
    # print('*'* 99)
    # print( result_search2['hits']['total'])
    # pp = pprint.PrettyPrinter(indent=4)
    # pp.pprint(result_search2['aggregations']['timeline']['buckets'])
    # print (result_search2['aggregations']['timeline']['buckets'])
    # print(type(result_search2.()))

    my_results_traffic = es_traffic['aggregations']['timeline']['buckets']
    x_traffic = []
    y_traffic = []
    for i in my_results_traffic:
        # epoch_time=datetime.fromtimestamp(i['key']/1000)
        epoch_time = i['key']

        # epoch_time= epoch_time.astimezone(tz.gettz('Adia/Bangkok'))
        date_str = str(epoch_time)
        x_traffic.append(date_str)
        y_traffic.append(str(i['doc_count']))
        
    # print(x_traffic)
    # print(y_traffic)
# End connect index_traffic
# connect index_misp
    # print('*'* 100)
    # print(x_traffic)
    # print('*'* 100)
    client_misp = Elasticsearch('http://192.168.1.77:9200', http_auth=('elastic', 'isylzjkoD3v'))
    es_misp = client_misp.search(index=index_misp,  body=query_body_misp, filter_path=['aggregations.timeline.*'])
    print('-'* 99)
    print(query_body_misp)
    # print(es_misp)
    print('-'* 99)
    # print( result_search2['hits']['total'])
    # pp = pprint.PrettyPrinter(indent=4)
    # pp.pprint(result_search2['aggregations']['timeline']['buckets'])
    # print (result_search2['aggregations']['timeline']['buckets'])
    # print(type(result_search2.()))

    my_results_misp = es_misp['aggregations']['timeline']['buckets']
    x_misp = []
    y_misp = []
    for i in my_results_misp:
        # ts = i['key']
        # date_str = datetime.utcfromtimestamp(ts).strftime('%H:%M:%S')
        # date_str = str(ts)
        epoch_time = i['key']
        # date_str = time.ctime(epoch_time)
        date_str = str(epoch_time)
        # print (date_str)
        x_misp.append(date_str)
        y_misp.append(str(i['doc_count']))
    # print(x_misp)
    # print(y_misp)
# End connect index_misp
# connect index_match
    client_match = Elasticsearch('http://192.168.1.77:9200', http_auth=('elastic', 'isylzjkoD3v'))
    es_match = client_match.search(index=index_match,  body=query_body_match, filter_path=['aggregations.timeline.*'])
    # print('*'* 99)
    # print(es_traffic)
    # print('*'* 99)
    # print( result_search2['hits']['total'])
    # pp = pprint.PrettyPrinter(indent=4)
    # pp.pprint(result_search2['aggregations']['timeline']['buckets'])
    # print (result_search2['aggregations']['timeline']['buckets'])
    # print(type(result_search2.()))

    my_results_match = es_match['aggregations']['timeline']['buckets']
    x_match = []
    y_match = []
    for i in my_results_match:
        # ts = i['key']
        # date_str = datetime.utcfromtimestamp(ts).strftime('%H:%M:%S')
        # date_str = str(ts)
        epoch_time = i['key']
        # date_str = time.ctime(epoch_time)
        date_str = str(epoch_time)
        # print (date_str)
        x_match.append(date_str)
        y_match.append(str(i['doc_count']))
        # print(x_traffic)
        # print(y_traffic)
# End connect index_match
# Start Tables
    es = Elasticsearch('http://192.168.1.77:9200', http_auth=('elastic', 'isylzjkoD3v'))
    resp = es.search(index=index_table, body= query_body_table,  filter_path=['hits.hits.*'])
    # result_count = client.count(index=index, body=query_body)
    # print('*'*10)
    # print (resp)
    # print('*'*10)
    data = []
    for hit in resp['hits']['hits']:
    
        # print("%(srcIP)s" % hit["_source"])
        col = []
        original_date_time_str = hit["_source"]["@timestamp"]
        date_time_str = original_date_time_str.split(".")
        date_time_obj = datetime.strptime(date_time_str[0], '%Y-%m-%dT%H:%M:%S')
        tz = timezone(timedelta(hours=7))
        new_time = date_time_obj.astimezone(tz)
        new_date_time_str = new_time.strftime("%Y-%m-%d %H:%M:%S")

        #print ("The new_time is", new_time)
        # col.append(original_date_time_str)
        col.append(new_date_time_str)
        col.append(hit["_source"]["srcIP"])
        col.append(hit["_source"]["srcPort"])
        col.append(hit["_source"]["dstIP"])
        col.append(hit["_source"]["dstPort"])
        col.append(hit["_source"]["enriched"]["misp"]["threat_indicator"]["feed"])
        col.append(hit["_source"]["enriched"]["misp"]["threat_indicator"]["type"])
        col.append(hit["_source"]["enriched"]["rule"]["category"])
        data.append(col)
# End Table
    # pp.pprint(x_misp)
    # pp.pprint(y_traffic)
    # print(','.join(x))
    # print("+"* 10)
    # context = {'segment': 'index', 'x_traffic' : ','.join(x_traffic), 'y_traffic' : ','.join(y_traffic)}
    # print(context)
    context = {'segment': 'index', 'x_traffic' : ','.join(x_traffic), 'y_traffic' : ','.join(y_traffic),'x_misp':','.join(x_misp),'y_misp':','.join(y_misp),'x_match':','.join(x_match),'y_match':','.join(y_match),'data': data}
    # print(context)
    html_template = loader.get_template('home/index.html')
    return HttpResponse(html_template.render(context, request))
# #-----------------------------------------------------------------
#     client2 = Elasticsearch('http://192.168.1.77:9200', http_auth=('elastic', 'isylzjkoD3v'))
#     client2.get(index="filebeat-udp*",id="*")
    
# #-----------------------------------------------------------------
    context = {'segment': 'index'}
    html_template = loader.get_template('home/index.html')
    return HttpResponse(html_template.render(context, request))

 
@login_required(login_url="/login/")
def pages(request):
    context = {}
    # All resource paths end in .html.
    # Pick out the html file name from the url. And load that template.
    try:

        load_template = request.path.split('/')[-1]

        if load_template == 'admin':
            return HttpResponseRedirect(reverse('admin:index'))
        context['segment'] = load_template

        html_template = loader.get_template('home/' + load_template)
        return HttpResponse(html_template.render(context, request))

    except template.TemplateDoesNotExist:

        html_template = loader.get_template('home/page-404.html')
        return HttpResponse(html_template.render(context, request))

    except:
        html_template = loader.get_template('home/page-500.html')
        return HttpResponse(html_template.render(context, request))
# Create your views here.
def cTimeUi(original_date_time_str): 
    date_time_str = original_date_time_str.split(".")
    date_time_obj = datetime.strptime(date_time_str[0], '%Y-%m-%dT%H:%M:%S')

    tz = timezone(timedelta(hours=7))
    new_time = date_time_obj.astimezone(tz)
    new_date_time_str = new_time.strftime("%Y-%m-%dT%H:%M:%S")

    return new_date_time_str


def cTimeSystem(original_date_time_str): 

    date_time_obj = datetime.strptime(original_date_time_str, '%Y-%m-%dT%H:%M:%S')

    tz = timezone(timedelta(hours=-7))
    new_time = date_time_obj.astimezone(tz)
    new_date_time_str = new_time.strftime("%Y-%m-%dT%H:%M:%S")

    return new_date_time_str

def report(request): 
    # print('*'* 99)
    
    start_time = request.GET.get('Starttime')
    # print(start_time)
    end_time = request.GET.get('Endtime')
    page = request.GET.get('page')
    action = request.GET.get('action')
    pages = request.GET.get('pages')
    print(type(page))
    print("action:",action)
    if action == "Next":
        page = int(page) + 1
    if action == "Back":
        if int(page) > 1:
            page = int(page) - 1
    if action == "New":
        page = 1
    if action == "start":
        page = 1
    if action == "end":
        page = pages
    # if action == "CSV":
    #     print("CSV")
        # psg(start_time,end_time)
        # return redirect(views.psg,start_time)
    if page is None:
        page = 1

    # print(end_time)
    # print('*'* 99)
    query_body = {
        "from": 10*(int(page)-1),
        "size": 10,
        "sort": [
            {
            "@timestamp": {
                "order": "desc"
            }
            }
        ],
        "query": {
            "query_string": {
                "query": "@timestamp: [now-1d TO now] AND enriched.misp.threat_indicator.feed: misp"
            }
        }
    }

    if start_time is not None and end_time is not None:
        new_start_time = cTimeSystem(start_time+":00")
        new_end_time = cTimeSystem(end_time+":00")
        # print('*'*10)
        # csv = psg()
        # print(start_time)
        # # print('*'*10)
        # print(new_start_time)
        # print('*'*10)
        query_body = {
            "from": 10*(int(page)-1),
            "size": 10,
            "sort": [
                {
                "@timestamp": {
                    "order": "desc"
                }
                }
            ],
            "query": {
                "query_string": {
                "query": "@timestamp: [" + new_start_time + " TO " + new_end_time + "] AND enriched.misp.threat_indicator.feed: misp"
                }
            }
        }
    else:
        now = datetime.now(pytz.timezone('Asia/Bangkok'))
        onedayago = datetime.now(pytz.timezone('Asia/Bangkok')) - timedelta(days = 1 )
        # print(now.strftime("%Y-%m-%dT%H:%M"))
        # print(onedayago.strftime("%Y-%m-%dT%H:%M"))
        start_time = onedayago.strftime("%Y-%m-%dT%H:%M")
        end_time = now.strftime("%Y-%m-%dT%H:%M")

    index = 'filebeat-udp*'
    es = Elasticsearch('http://192.168.1.77:9200', http_auth=('elastic', 'isylzjkoD3v'))
    resp = es.search(index=index, body=query_body,  filter_path=['hits.*'])
    # result_count = client.count(index=index, body=query_body)
    # pprint.pprint(resp)
    data = []
    total = resp['hits']['total']['value']
    for hit in resp['hits']['hits']:
        # print("%(srcIP)s" % hit["_source"])
        col = []
        original_date_time_str = hit["_source"]["@timestamp"]
        new_date_time_str =  cTimeUi(original_date_time_str)

        #print ("The new_time is", new_time)
        # col.append(original_date_time_str)
        col.append(new_date_time_str)
        col.append(hit["_source"]["srcIP"])
        col.append(hit["_source"]["srcPort"])
        col.append(hit["_source"]["dstIP"])
        col.append(hit["_source"]["dstPort"])
        col.append(hit["_source"]["enriched"]["misp"]["threat_indicator"]["feed"])
        col.append(hit["_source"]["enriched"]["misp"]["threat_indicator"]["type"])
        col.append(hit["_source"]["enriched"]["rule"]["category"])
        data.append(col)
    


    template = loader.get_template('home/report.html')
    x = total // 10
    y = total % 10
    if y > 0 :
        pages = x+1
    else:
        pages = x
    if int(page) > pages :
        page = pages
    context = {
        'data': data,
        'StartTime':start_time,
        'EndTime'  : end_time,
        'pages' : pages,
        'page' : page,
        'total': total

    }

    return HttpResponse(template.render(context, request))

# Students name
# NAME = ['Riya','Suzzane','George','Zoya','Smith','Henry']
# QUIZ Subject
# SUBJECT = ['CHE','PHY','CHE','BIO','ENG','ENG']   

# def psg(request):
#     # start=request.GET.get('start')
#     # print(start)
#     # print(end)
#     response = HttpResponse('text/csv')
#     # print(response)
#     response['Content-Disposition'] = 'attachment; filename=quiz.csv'
# # Create the CSV writer using the HttpResponse as the "file"
#     writer = csv.writer(response)
#     # print(writer)
#     writer.writerow(['Student Name', 'Quiz Subject'])
#     for (name, sub) in zip(NAME, SUBJECT):
#         writer.writerow([name, sub])
#     # print("brad")
#     # template = loader.get_template('home/report.html')

#     return response

def export_csv(request):
    start_time = request.GET.get('Starttime')
    end_time = request.GET.get('Endtime')
    
    query_body = {
          "from": 0,
        "size": 10000,
        "sort": [
            {
            "@timestamp": {
                "order": "desc"
            }
            }
        ],
        "query": {
            "query_string": {
                "query": "@timestamp: [now-1d TO now] AND enriched.misp.threat_indicator.feed: misp"
            }
        }
    }

    if start_time is not None and end_time is not None:
        new_start_time = cTimeSystem(start_time)
        new_end_time = cTimeSystem(end_time)

        query_body = {
            "sort": [
                {
                "@timestamp": {
                    "order": "desc"
                }
                }
            ],
            "query": {
                "query_string": {
                "query": "@timestamp: [" + new_start_time + " TO " + new_end_time + "] AND enriched.misp.threat_indicator.feed: misp"
                }
            }
        }

    index = 'filebeat-udp*'
    es = Elasticsearch('http://192.168.1.77:9200', http_auth=('elastic', 'isylzjkoD3v'))
    resp = es.search(index=index, body=query_body,  filter_path=['hits.hits.*'])

    data = []
    for hit in resp['hits']['hits']:
        col = []
        original_date_time_str = hit["_source"]["@timestamp"]
        new_date_time_str =  cTimeUi(original_date_time_str)
        col.append(new_date_time_str)
        col.append(hit["_source"]["srcIP"])
        col.append(hit["_source"]["srcPort"])
        col.append(hit["_source"]["dstIP"])
        col.append(hit["_source"]["dstPort"])
        col.append(hit["_source"]["enriched"]["misp"]["threat_indicator"]["feed"])
        col.append(hit["_source"]["enriched"]["misp"]["threat_indicator"]["type"])
        col.append(hit["_source"]["enriched"]["rule"]["category"])
        data.append(col)

    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="Report.csv"'

    writer = csv.writer(response)
    # <th>Time</th>
    # <th>srcIP</th>
    # <th>srcPort</th>
    # <th>dstIP</th>
    # <th>dstPort</th>
    # <th>Indicator</th>
    # <th>type</th>
    # <th>Category</th>
    writer.writerow(['Time', 'srcIP', 'srcPort','dstIP','dstPort','Indicator','type','Category'])

    for item in data:
        writer.writerow(item)
    return response