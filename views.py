from django.shortcuts import render
from .models import Msgs, Chat, Invite, User, AccountAuth, TempAccess, TempAuth, TempKey, TempId, TempTimeout
from django.http import JsonResponse
import json
import secrets
from django.conf.urls.static import static
from django.contrib.staticfiles import finders
import Crypto
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Hash import SHA512
from Crypto.Random import get_random_bytes
import base64
from django.http import HttpResponse
import time
import datetime
from django.http import StreamingHttpResponse
import hashlib
import uuid

def index(request):
    return render(request, 'index.html')

def join(request):
    return render(request, 'atemp.html')

def getTKey(request):
    result = ['auth-fail']
    if request.method == 'POST':
        tcid = json.loads(request.body.decode('utf-8'))['cid']
        get_chat = Chat.objects.get(cid=tcid)
        auth_test = getattr(get_chat, 'temp')
        user_test = json.loads(request.body.decode('utf-8'))['auth'] == str(getattr(TempAuth.objects.get(cid=tcid), 'uuid'))
        if auth_test and user_test:
            gettemp = TempKey.objects.get(cid = tcid)
            key = getattr(gettemp, 'key')
            iv = getattr(gettemp, 'iv')
            TempKey.objects.filter(cid = tcid).delete()
            TempTimeout(cid = tcid).save()
            result = [key, iv]
    return JsonResponse(result, safe=False)

def createTemp(request):
    cid = generateUCID()
    chat = Chat(cid = cid, temp = True)
    chat.save()
    temp = TempAccess(cid = cid)
    temp.save()
    auth = TempAuth(cid = cid)
    auth.save()
    tempid = TempId(cid = cid, ad = True)
    tempid.save()
    tempid1 = TempId(cid = cid)
    tempid1.save()
    id = getattr(TempId.objects.get(cid = cid, ad = True), 'tid')
    uuid = getattr(TempAccess.objects.get(cid = cid), 'tid')
    auth = getattr(TempAuth.objects.get(cid=cid), 'uuid')
    return render(request, 'ctemp.html', {'cid': cid, 'uuid': uuid, 'auth': auth, 'id': id})

def tempPurge(request):
    result = ['auth-fail']
    tcid = json.loads(request.body.decode('utf-8'))['cid']
    get_chat = Chat.objects.get(cid=tcid)
    auth_test = ''
    user_test = ''
    auth_test = getattr(get_chat, 'temp')
    user_test = json.loads(request.body.decode('utf-8'))['auth'] == str(getattr(TempAuth.objects.get(cid=tcid), 'uuid'))
    #print(auth_test)
    #print(user_test)
    if auth_test:
        if user_test:
            TempAuth.objects.filter(cid=tcid).delete()
            Chat.objects.filter(cid=tcid).delete()
            Msgs.objects.filter(cid=tcid).delete()
            TempTimeout.objects.get(cid=tcid).delete()
            TempKey.objects.filter(cid=tcid).delete()
            TempAccess.objects.filter(cid=tcid).delete()
            TempId.objects.filter(cid=tcid).delete()
            msg = Msgs(json = json.loads('{"message": "PURGED"}'), cid = tcid)
            msg.save()
            #Msgs.objects.filter(cid=tcid).delete()
            result = ['success']
    return JsonResponse(result, safe=False)

def setTempKey(request):
    result = ['auth-fail']
    if request.method == 'POST':
        tcid = json.loads(request.body.decode('utf-8'))['cid']
        get_chat = Chat.objects.get(cid=tcid)
        auth_test = getattr(get_chat, 'temp')
        user_test = json.loads(request.body.decode('utf-8'))['auth'] == str(getattr(TempAuth.objects.get(cid=tcid), 'uuid'))
        #print(tcid, auth_test, user_test, request.GET.get('auth'), type(request.GET.get('auth')), getattr(TempAuth.objects.get(cid=tcid), 'uuid'), type(str(getattr(TempAuth.objects.get(cid=tcid), 'uuid'))))
        if auth_test and user_test:
            key = TempKey(cid = tcid, key = json.loads(request.body.decode('utf-8'))['key'], iv = json.loads(request.body.decode('utf-8'))['iv'])
            key.save()
            result = ['success']
    return JsonResponse(result, safe=False)

def newTemp(request):
    result = ['auth-fail']
    if request.method == 'GET':
        tuid = request.GET.get('uid')
        tid = request.GET.get('id')
        tidt = request.GET.get('idt')
        tuk = request.GET.get('uk')

        salt_auth = getattr(AccountAuth.objects.get(uid=tuid), 'salt')
        hash_auth = PBKDF2_HASH(salt_auth, tid)

        salt_user = getattr(User.objects.get(uid=tuid), 'salt')
        hash_user = PBKDF2_HASH(salt_user, tuk)

        auth_test1 = AccountAuth.objects.filter(uid=tuid, uuid=hash_auth, time=tidt).exists()
        auth_test2 = User.objects.filter(uid=tuid, uk=hash_user).exists()
        if auth_test1:
            if auth_test2:
                tcid = generateUCID()
                chat = Chat(cid = tcid, users = tuid, temp = True)
                chat.save()
                temp = TempAccess(cid = tcid)
                temp.save()
                auth = TempAuth(cid = tcid)
                auth.save()
                getuuid = TempAccess.objects.get(cid = tcid)
                uuid = getattr(getuuid, 'tid')
                try:
                    chats = json.loads(User.objects.get(uid=tuid).chats)
                    if tcid in chats.keys():
                        print('pass')
                    else:
                        chats[tcid] = 'INIT'
                except:
                    list = {}
                    list[tcid] = 'INIT'
                    chats = list
                user = User.objects.filter(uid=tuid)
                user.update(chats = json.dumps(chats))
                result = [uuid]
    return JsonResponse(result, safe=False)

def getTemp(request):
    result = ['auth-fail']
    if request.method == 'GET':
        tuuid = request.GET.get('id')
        try:
            get = TempAccess.objects.get(tid=tuuid)
            cid = getattr(get, 'cid')
            TempAccess.objects.filter(tid=tuuid).delete()
        except:
            cid = 'auth-fail'
        result = [cid, getattr(Chat.objects.get(cid=cid), 'users'), getattr(TempAuth.objects.get(cid=cid), 'uuid')]
    return JsonResponse(result, safe=False)

def joinTemp(request):
    result = ['auth-fail']
    if request.method == 'GET':
        tuuid = request.GET.get('id')
        try:
            get = TempAccess.objects.get(tid=tuuid)
            cid = getattr(get, 'cid')
            TempAccess.objects.filter(tid=tuuid).delete()
            msg = Msgs(json = json.loads('{"message": "JOINED"}'), cid = cid)
            msg.save()
            result = [cid, getattr(TempAuth.objects.get(cid=cid), 'uuid'), getattr(TempId.objects.get(cid=cid, ad=False), 'tid')]
        except:
            result = ['auth-fail']
    return JsonResponse(result, safe=False)

def tempKey(request):
    result = ['auth-fail']
    if request.method == "POST":
        tcid = request.GET.get('cid')
        get_chat = Chat.objects.get(cid=tcid)
        auth_test = ''
        user_test = ''
        auth_test = getattr(get_chat, 'temp')
        user_test = request.GET.get('auth') == str(getattr(TempAuth.objects.get(cid=tcid), 'uuid'))
        if auth_test and user_test:
            get_user = getattr(get_chat, 'users')
            chats = json.loads(User.objects.get(uid=get_user).chats)
            chats[tcid] = json.loads(request.body.decode('utf-8'))['key']
            user = User.objects.filter(uid=get_user)
            user.update(chats = json.dumps(chats))
            TempAuth.objects.filter(cid=tcid).delete()
            result = ['success']
    return JsonResponse(result, safe=False)

def getTempKey(request):
    result = ['auth-fail']
    if request.method == 'GET':
        tcid = request.GET.get('cid')
        tuid = request.GET.get('uid')
        tid = request.GET.get('id')
        tidt = request.GET.get('idt')
        tuk = request.GET.get('uk')

        salt_auth = getattr(AccountAuth.objects.get(uid=tuid), 'salt')
        hash_auth = PBKDF2_HASH(salt_auth, tid)

        salt_user = getattr(User.objects.get(uid=tuid), 'salt')
        hash_user = PBKDF2_HASH(salt_user, tuk)

        auth_test1 = AccountAuth.objects.filter(uid=tuid, uuid=hash_auth, time=tidt).exists()
        auth_test2 = User.objects.filter(uid=tuid, uk=hash_user).exists()
        if auth_test1:
            if auth_test2:
                user = User.objects.get(uid=tuid)
                cids = getattr(user, 'chats')
                key = json.loads(cids)[tcid]
                result = [key]
    return JsonResponse(result, safe=False)

def sendInvite(request):
    result = ['auth-fail']
    if request.method == 'POST':
        tuid = request.GET.get('uid')
        auid = request.GET.get('auid')
        tid = request.GET.get('id')
        tidt = request.GET.get('idt')
        tuk = request.GET.get('uk')

        salt_auth = getattr(AccountAuth.objects.get(uid=auid), 'salt')
        hash_auth = PBKDF2_HASH(salt_auth, tid)

        salt_user = getattr(User.objects.get(uid=auid), 'salt')
        hash_user = PBKDF2_HASH(salt_user, tuk)

        auth_test1 = AccountAuth.objects.filter(uid=auid, uuid=hash_auth, time=tidt).exists()
        auth_test2 = User.objects.filter(uid=auid, uk=hash_user).exists()
        if auth_test1:
            if auth_test2:
                if Chat.objects.filter(cid=request.GET.get('cid')).exists(): #TBD check that user is admin
                    tcid = request.GET.get('cid')

                else:
                    tcid = generateUCID()

                    chat = Chat(cid = tcid, users = request.GET.get('auid'))
                    chat.save()
                invite = Invite(sender = auid, cid = tcid, uid = tuid, msg = json.loads(request.body.decode("utf-8"))['req'], key = json.loads(request.body.decode("utf-8"))['inv_key'])
                invite.save()
                getuser = User.objects.get(uid=auid)

                try:
                    chats = json.loads(User.objects.get(uid=auid).chats)
                    if tcid in chats.keys():
                        print('pass')
                    else:
                        chats[tcid] = json.loads(request.body.decode('utf-8'))['key']

                except:
                    list = {}
                    list[tcid] = json.loads(request.body.decode('utf-8'))['key']
                    chats = list

                user = User.objects.filter(uid=auid)
                user.update(chats = json.dumps(chats))
                result = ['success', tcid]
    return JsonResponse(result, safe=False)

def resInvite(request):
    result = ['auth-fail']
    if request.method == 'GET':
        tuid = request.GET.get('uid')
        tid = request.GET.get('id')
        tidt = request.GET.get('idt')
        tuk = request.GET.get('uk')

        salt_auth = getattr(AccountAuth.objects.get(uid=tuid), 'salt')
        hash_auth = PBKDF2_HASH(salt_auth, tid)

        salt_user = getattr(User.objects.get(uid=tuid), 'salt')
        hash_user = PBKDF2_HASH(salt_user, tuk)

        auth_test1 = AccountAuth.objects.filter(uid=tuid, uuid=hash_auth, time=tidt).exists()
        auth_test2 = User.objects.filter(uid=tuid, uk=hash_user).exists()
        if auth_test1:
            if auth_test2:
                decision = request.GET.get('dec')
                invite = request.GET.get('inv')

                inv_obj = Invite.objects.get(uid=tuid, cid=invite)

                if decision == 'accept':
                    try:
                        chats = json.loads(User.objects.get(uid=tuid).chats)
                        if invite in chats.keys():
                            print('pass')
                        else:
                            chats[invite] = getattr(inv_obj, 'key')

                    except:
                        list = {}
                        list[invite] = getattr(inv_obj, 'key')
                        chats = list

                    chat = Chat.objects.filter(cid=invite)
                    getchat = Chat.objects.get(cid=invite)
                    chat.update(users = getattr(getchat, 'users') + '|' + tuid)
                    user = User.objects.filter(uid=tuid)
                    user.update(chats = json.dumps(chats))
                    inv_obj.delete()
                    result = ['success']
                    return JsonResponse(result, safe=False)

                if decision == 'reject':
                    inv_obj.delete()
                    result = ['success']
                    return JsonResponse(result, safe=False)

    return JsonResponse(result, safe=False)

def getChats(request):
    def chat_stream():
        if request.method == 'GET':
            tuid = request.GET.get('uid')
            tid = request.GET.get('id')
            tidt = request.GET.get('idt')
            tuk = request.GET.get('uk')

            salt_auth = getattr(AccountAuth.objects.get(uid=tuid), 'salt')
            hash_auth = PBKDF2_HASH(salt_auth, tid)

            salt_user = getattr(User.objects.get(uid=tuid), 'salt')
            hash_user = PBKDF2_HASH(salt_user, tuk)

            auth_test1 = AccountAuth.objects.filter(uid=tuid, uuid=hash_auth, time=tidt).exists()
            auth_test2 = User.objects.filter(uid=tuid, uk=hash_user).exists()
            if auth_test1:
                if auth_test2:
                    user = User.objects.get(uid=tuid)
                    print(user)
                    cids = getattr(user, 'chats')
                    cid_length = len(cids)

                    cid_list = []
                    print(user)
                    print(cids)
                    try:
                        for key, value in json.loads(cids).items():
                            cid_list.append(key)
                    except:
                        for key, value in cids.items():
                            cid_list.append(key)

                    mergeSort(cid_list, 0, len(cid_list) - 1, 0)

                    for chat in cid_list:
                        yield 'data:%s\n\n' % json.dumps({'chat':chat, 'key':json.loads(cids)[chat]}, ensure_ascii=False)

                    if Invite.objects.filter(uid=tuid).exists():
                        invites = Invite.objects.filter(uid=tuid)
                        invite_list = []
                        for invite in invites:
                            invite_list.append(getattr(invite, 'cid'))
                        mergeSort(invite_list, 0, len(invite_list) - 1, 1)
                        for invite in invite_list:
                            get_inv = Invite.objects.get(uid=tuid, cid=invite)
                            yield 'data:%s\n\n' % json.dumps({'invite':invite, 'req': getattr(get_inv, 'msg'), 'sender': getattr(get_inv, 'sender')}, ensure_ascii=False)

                    yield 'data:%s\n\n' % json.dumps({'status': 'init-finished'}, ensure_ascii=False)
                    try:
                        get_inv_id = Invite.objects.filter(uid=tuid).latest('date', 'time')
                        prev_inv_id = getattr(get_inv_id, 'pk')
                    except:
                        prev_inv_id = -1
                    t = datetime.datetime.now()
                    while True:
                        delta = datetime.datetime.now() - t
                        if delta.seconds >= 90:
                            yield 'data:%s\n\n' % 'pass'
                            t = datetime.datetime.now()

                        try:
                            get_curr_inv_id = Invite.objects.filter(uid=tuid).latest('date', 'time')
                            curr_inv_id = getattr(get_curr_inv_id, 'pk')
                        except:
                            curr_inv_id = -1

                        if curr_inv_id > prev_inv_id:
                            prev_inv_id = curr_inv_id
                            get_invite = getattr(get_curr_inv_id, 'cid')
                            get_inv = Invite.objects.get(uid=tuid, cid=get_invite)
                            yield 'data:%s\n\n' % json.dumps({'invite': get_invite, 'req': getattr(get_inv, 'msg'), 'sender': getattr(get_inv, 'sender')}, ensure_ascii=False)

                        curr_user = User.objects.get(uid=tuid)
                        curr_cids = getattr(curr_user, 'chats')
                        curr_list = []

                        try:
                            for key, value in json.loads(curr_cids).items():
                                if not key in cid_list:
                                    curr_list.append(key)
                        except:
                            for key, value in curr_cids.items():
                                if not key in cid_list:
                                    curr_list.append(key)

                        mergeSort(curr_list, 0, len(curr_list) - 1, 0)

                        for chat in curr_list:
                            cid_list.append(key)
                            yield 'data:%s\n\n' % json.dumps({'chat':chat, 'key':json.loads(curr_cids)[chat]}, ensure_ascii=False)


                else:
                    yield 'data:%s\n\n' % ['user-mismatch']
            else:
                yield 'data:%s\n\n' % ['auth-fail']
        else:
            yield 'data:%s\n\n' % ['no-params']
    stream = chat_stream()
    response = StreamingHttpResponse(stream, content_type='text/event-stream')
    response['Cache-Control'] = 'no-cache'
    return response

def serveKey(request):
    result = ['auth-fail', '-----BEGIN PUBLIC KEY-----auth-fail-----END PUBLIC KEY-----']
    if request.method == 'GET':
        try:
            mode = request.GET.get('m')
        except:
            mode = ''
        if mode != None and int(mode) == 1:
            tcid = request.GET.get('cid')
            tuid = request.GET.get('uid')
            get_chat = Chat.objects.get(cid=tcid)

            auth_test1 = getattr(get_chat, 'temp')
            auth_test2 = True
        else:
            tuid = request.GET.get('uid')
            auid = request.GET.get('auid')
            tid = request.GET.get('id')
            tidt = request.GET.get('idt')
            tuk = request.GET.get('uk')

            salt_auth = getattr(AccountAuth.objects.get(uid=auid), 'salt')
            hash_auth = PBKDF2_HASH(salt_auth, tid)

            salt_user = getattr(User.objects.get(uid=auid), 'salt')
            hash_user = PBKDF2_HASH(salt_user, tuk)

            auth_test1 = AccountAuth.objects.filter(uid=auid, uuid=hash_auth, time=tidt).exists()
            auth_test2 = User.objects.filter(uid=auid, uk=hash_user).exists()
        if auth_test1:
            if auth_test2:
                try:
                    getuser = User.objects.get(uid=tuid)
                    result = ['success', getattr(getuser, 'pbk')]
                except:
                    result = ['auth-fail', '-----BEGIN PUBLIC KEY-----auth-fail-----END PUBLIC KEY-----']
    return JsonResponse(result, safe=False)

def newKeys(request):
    result = ['error']
    if request.method == 'GET':
        if User.objects.filter(uid=request.GET.get('uid')).exists() and getattr(User.objects.get(uid=request.GET.get('uid')), 'spk') == '':
            user = User.objects.filter(uid=request.GET.get('uid'))
            serverkeypair = Crypto.PublicKey.RSA.generate(4096)
            spk = serverkeypair.publickey().exportKey(format='PEM', passphrase=None, pkcs=8, protection=None, randfunc=None)
            sprk = serverkeypair.exportKey(format='PEM', passphrase=None, pkcs=8, protection=None, randfunc=None)
            spk = spk.decode()
            result = ['success', spk]
            user.update(spk = spk)
            user.update(sprk = sprk.decode())

    return JsonResponse(result, safe=False)

def solveServerChallenge(request):
    result = ['error']
    if request.method == 'GET':
        user = User.objects.get(uid=request.GET.get('uid'))
        sprk = getattr(user, 'sprk')
        key = RSA.importKey(sprk.encode())
        cipher = PKCS1_OAEP.new(key, SHA256)
        tsd = request.GET.get('seed')
        tsd = base64.b64decode(b64url_to_b64(tsd))
        seed = cipher.decrypt(tsd)
        seed = base64.b64encode(seed).decode()
        result = ['success', seed]
    return JsonResponse(result, safe=False)

def newUser(request):
    result = ['error']
    if request.method == 'GET':
        if User.objects.filter(uid=request.GET.get('uid')).exists() and getattr(User.objects.get(uid=request.GET.get('uid')), 'pbk') == '':
            user = User.objects.filter(uid=request.GET.get('uid'))
            try:
                salt = secrets.token_bytes(64)
                hash = ''
                hash = PBKDF2_HASH(salt, request.GET.get('uk'))
                user.update(pbk=request.GET.get('pbk'))
                user.update(uk=hash)
                user.update(salt=salt)
                result = ['success']
                check = User.objects.get(uid=request.GET.get('uid'))

            except:
                result = ['error']
    return JsonResponse(result, safe=False)

def userChallenge(request):
    result = ['auth-fail']
    if request.method == 'GET':
        tuid = request.GET.get('uid')
        tuk = request.GET.get('uk')

        salt_user = getattr(User.objects.get(uid=tuid), 'salt')
        hash_user = PBKDF2_HASH(salt_user, tuk)

        auth_test = User.objects.filter(uid=tuid, uk=hash_user).exists()
        if auth_test:
            past = AccountAuth.objects.filter(uid=tuid).delete()
            gc = generateChallenge(getattr(User.objects.get(uid=tuid), 'pbk'), tuid, 1)
            result = [gc[0].decode('utf-8'), gc[1]]

    return JsonResponse(result, safe=False)

def rec(request):
    if request.method == 'POST':
        tcid = json.loads(request.body.decode('utf-8'))['cid']
        get_chat = Chat.objects.get(cid=tcid)
        auth_test = getattr(get_chat, 'temp')
        user_test = json.loads(request.body.decode('utf-8'))['auth'] == str(getattr(TempAuth.objects.get(cid=tcid), 'uuid'))
        if auth_test:
            if user_test:
                try:
                    dict = json.loads(request.body.decode("utf-8"))
                    del dict['cid']
                    del dict['auth']
                    msg = Msgs(json = dict, cid = tcid)
                    msg.save()
                    response = {'success': True}
                    return JsonResponse(response, safe=False)
                except:
                    return render(request)
            else:
                return JsonResponse({'error': 'user-mismatch'}, safe=False)
    return render(request, 'loading.html')


def trans(request):
    list = ["auth_fail"]
    tcid = json.loads(request.body.decode('utf-8'))['cid']
    get_chat = Chat.objects.get(cid=tcid)
    auth_test = getattr(get_chat, 'temp')
    user_test = json.loads(request.body.decode('utf-8'))['auth'] == str(getattr(TempAuth.objects.get(cid=tcid), 'uuid'))
    if auth_test:
        if user_test:
            messages = Msgs.objects.filter(cid=tcid)
            list = [[getattr(message, 'json'), getattr(message, 'time'), getattr(message, 'date')] for message in messages]
            list = [x for x in list if 'message' in x[0] and x[0]['message'] != '']
        else:
            list = ["user-mismatch"]

    response = JsonResponse(list, safe=False)
    return response

def generateUCID():
    ucid = ''
    d = {}

    with open(finders.find('../static/wordlist.txt'), 'r') as f:
        num_lines = sum(1 for line in f)
        f.seek(0)
        lines = f.readlines()

    while(len(ucid) < 20 and not Chat.objects.filter(cid=ucid).exists() and not Msgs.objects.filter(cid=ucid).exists()):
        rand = secrets.randbelow(num_lines)
        ucid += lines[rand][:len(lines[rand]) - 1] + "-"
    ucid = ucid[:len(ucid) - 1]
    return ucid

def generateUUID():
    uuid = ''
    d = {}

    with open(finders.find('../static/wordlist.txt'), 'r') as f:
        num_lines = sum(1 for line in f)
        f.seek(0)
        lines = f.readlines()

    while(len(uuid) < 20 and not User.objects.filter(uid=uuid).exists()):
        rand = secrets.randbelow(num_lines)
        uuid += lines[rand][:len(lines[rand]) - 1] + "-"
    uuid = uuid[:len(uuid) - 1]
    return uuid

def base64url_to_base64(base64url):
    base64url = base64url.replace('-', '+').replace('_', '/')
    padding = '=' * (4 - (len(base64url) % 4))
    return base64url + padding

def b64url_to_b64(str):
    return str.replace('-', '+').replace('_', '/')

def generateChallenge(pbk, tcid, type):
    uuid = secrets.token_hex(64)
    salt = secrets.token_bytes(64)

    hash = ''
    hash = PBKDF2_HASH(salt, uuid)

    gettime = datetime.datetime.now()
    tstr = str(gettime.hour) + "-" + str(gettime.minute) + "-" + str(gettime.second) + "-" + str(gettime.microsecond)

    auth = AccountAuth(uid = tcid, uuid = hash, salt=salt, time = tstr)

    auth.save()

    bkey = pbk
    bkey = bkey[26:-24]
    bkey = json.loads(bkey)

    e = int.from_bytes(base64.b64decode(base64url_to_base64(bkey['e'])), "big")
    n = int.from_bytes(base64.b64decode(base64url_to_base64(bkey['n'])), "big")
    rsakey = RSA.construct((n, e), consistency_check=True)
    cipher = PKCS1_OAEP.new(rsakey, SHA256)

    challenge = cipher.encrypt(uuid.encode())
    challenge = base64.b64encode(challenge)
    return [challenge,tstr]

def tranStream(request):
    def msg_stream():
        id = request.GET.get('id')
        auth_test = TempId.objects.filter(tid = id).exists()
        if auth_test:
            tcid = getattr(TempId.objects.get(tid = id), 'cid')
            user_test = True
        else:
            tcid = 'authfail'
            user_test = False
        print(id, tcid, auth_test, user_test)
        if auth_test:
            if user_test:
                type1 = getattr(TempId.objects.get(tid = id), 'ad')
                print(type1)
                if not type1:
                    print(type1, 'FALSE')
                    TempId.objects.filter(tid = id).delete()
                    TempId(cid = tcid).save()
                    yield 'data:%s\n\n' % ['ID:',getattr(TempId.objects.get(cid=tcid, ad=type1), 'tid')]
                try:
                    prev = Msgs.objects.filter(cid=tcid).latest('date', 'time')
                    previd = getattr(prev, 'pk')
                except:
                    previd = -1
                t = datetime.datetime.now()
                while True:
                    delta = datetime.datetime.now() - t
                    if delta.seconds >= 90:
                        yield 'data:%s\n\n' % 'pass'
                        t = datetime.datetime.now()
                    try:
                        curr = Msgs.objects.filter(cid=tcid).latest('date', 'time')
                        currid = getattr(curr, 'pk')
                    except:
                        currid = -1
                    if currid > previd:
                        previd = currid
                        msg = getattr(curr, 'json')

                        messages = Msgs.objects.filter(cid=tcid).latest('date', 'time')
                        list = json.dumps([msg,str(getattr(messages, 'time')),str(getattr(messages, 'date'))])
                        yield 'data:%s\n\n' % list
            else:
                yield 'data:%s\n\n' % ['user-mismatch']
        else:
            yield 'data:%s\n\n' % ['auth-fail']
    stream = msg_stream()
    response = StreamingHttpResponse(stream, content_type='text/event-stream')
    response['Cache-Control'] = 'no-cache'
    return response

def merge_latest_chat(arr, l, m, r):
    n1 = m - l + 1
    n2 = r - m

    L = [0] * (n1)
    R = [0] * (n2)

    for i in range(0, n1):
        L[i] = arr[l + i]

    for j in range(0, n2):
        R[j] = arr[m + 1 + j]

    i = 0
    j = 0
    k = l

    while i < n1 and j < n2:
        try:
            L_latest = Msgs.objects.filter(cid=L[i]).latest('date', 'time')
            L_pk = getattr(L_latest, 'pk')
        except:
            L_pk = 0
        try:
            R_latest = Msgs.objects.filter(cid=R[j]).latest('date', 'time')
            R_pk = getattr(R_latest, 'pk')
        except:
            R_pk = 0

        if L_pk <= R_pk:
            arr[k] = L[i]
            i += 1
        else:
            arr[k] = R[j]
            j += 1
        k += 1

    while i < n1:
        arr[k] = L[i]
        i += 1
        k += 1

    while j < n2:
        arr[k] = R[j]
        j += 1
        k += 1

def merge_latest_invite(arr, l, m, r):
    n1 = m - l + 1
    n2 = r - m

    L = [0] * (n1)
    R = [0] * (n2)

    for i in range(0, n1):
        L[i] = arr[l + i]

    for j in range(0, n2):
        R[j] = arr[m + 1 + j]

    i = 0
    j = 0
    k = l

    while i < n1 and j < n2:
        L_latest = Invite.objects.filter(cid=L[i]).latest('date', 'time')
        R_latest = Invite.objects.filter(cid=R[j]).latest('date', 'time')

        if getattr(L_latest, 'pk') <= getattr(R_latest, 'pk'):
            arr[k] = L[i]
            i += 1
        else:
            arr[k] = R[j]
            j += 1
        k += 1

    while i < n1:
        arr[k] = L[i]
        i += 1
        k += 1

    while j < n2:
        arr[k] = R[j]
        j += 1
        k += 1

def mergeSort(arr, l, r, o):
    if l < r:

        m = l+(r-l)//2

        mergeSort(arr, l, m, o)
        mergeSort(arr, m+1, r, o)
        if o == 0:
            merge_latest_chat(arr, l, m, r)
        if o == 1:
            merge_latest_invite(arr, l, m, r)

def PBKDF2_HASH(salt, plain):
    plain = plain.encode('utf-8')
    if isinstance(salt, str):
        salt = str2bytes(salt)
    hashed = hashlib.pbkdf2_hmac('sha512', plain, salt, 1000000)
    return base64.b64encode(hashed)

def str2bytes(byte_string):
    return eval(byte_string)
