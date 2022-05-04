# from django.shortcuts import render
# from ntpath import join
# from elasticsearch import Elasticsearch
# from django import template
# from django.contrib.auth.decorators import login_required
# from django.http import HttpResponse, HttpResponseRedirect
# from django.template import loader
# from django.urls import reverse
# from datetime import datetime, timedelta, timezone
# from dateutil import tz

# # Create your views here.
# def cTimeUi(original_date_time_str): 
#     date_time_str = original_date_time_str.split(".")
#     date_time_obj = datetime.strptime(date_time_str[0], '%Y-%m-%dT%H:%M:%S')

#     tz = timezone(timedelta(hours=7))
#     new_time = date_time_obj.astimezone(tz)
#     new_date_time_str = new_time.strftime("%Y-%m-%d %H:%M:%S")

#     return new_date_time_str


# def cTimeSystem(original_date_time_str): 

#     date_time_obj = datetime.strptime(original_date_time_str, '%Y-%m-%d %H:%M:%S')

#     tz = timezone(timedelta(hours=-7))
#     new_time = date_time_obj.astimezone(tz)
#     new_date_time_str = new_time.strftime("%Y-%m-%dT%H:%M:%S")

#     return new_date_time_str

# def report(request): 
#     start_time = request.GET.get('Starttime')
#     end_time = request.GET.get('Endtime')
    
#     query_body = {
#         "from": 0,
#         "size": 10,
#         "sort": [
#             {
#             "@timestamp": {
#                 "order": "desc"
#             }
#             }
#         ],
#         "query": {
#             "query_string": {
#                 "query": "@timestamp: [now-1d TO now] AND enriched.misp.threat_indicator.feed: misp"
#             }
#         }
#     }

#     if start_time is not None and end_time is not None:
#         new_start_time = cTimeSystem(start_time)
#         new_end_time = cTimeSystem(end_time)
#         # print(start_time)
#         # print(new_start_time)

#         query_body = {
#             "from": 0,
#             "size": 10,
#             "sort": [
#                 {
#                 "@timestamp": {
#                     "order": "desc"
#                 }
#                 }
#             ],
#             "query": {
#                 "query_string": {
#                 "query": "@timestamp: [" + new_start_time + " TO " + new_end_time + "] AND enriched.misp.threat_indicator.feed: misp"
#                 }
#             }
#         }

#     index = 'filebeat-udp*'
#     es = Elasticsearch('http://192.168.1.77:9200', http_auth=('elastic', 'isylzjkoD3v'))
#     resp = es.search(index=index, body=query_body,  filter_path=['hits.hits.*'])
#     # result_count = client.count(index=index, body=query_body)
#     # print (resp)
#     data = []
#     for hit in resp['hits']['hits']:
#         # print("%(srcIP)s" % hit["_source"])
#         col = []
#         original_date_time_str = hit["_source"]["@timestamp"]
#         new_date_time_str =  cTimeUi(original_date_time_str)

#         #print ("The new_time is", new_time)
#         col.append(original_date_time_str)
#         col.append(new_date_time_str)
#         col.append(hit["_source"]["srcIP"])
#         col.append(hit["_source"]["dstIP"])
#         data.append(col)



#     template = loader.get_template('home/templates/report.html')
#     context = {
#         'data': data
#     }
#     return HttpResponse(template.render(context, request))