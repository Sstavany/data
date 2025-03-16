import requests, binascii, re, random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from protobuf_decoder.protobuf_decoder import Parser
from datetime import datetime
import json
import telebot
from concurrent.futures import ThreadPoolExecutor

# قوائم التوكنات
SPAM_TOKENS = [
    ("3811592035", "94076E2447C524E18B4CAA27A62526C95230DD7995B35F782E4AB09481AFCC80"),
    ("3811610211", "A25AC64DC4A00F13D89BD81CB986D551EBE8DD7F6AF61A2F47D9F50835EFCD13"),
    ("3522019485", "D7485A23824C284E9828C0881113A9E97D89984A4AFC454D8999E067DC2CEB94"),
    ("3230720524", "968C078430FC3BF41A3C88D0DB0FB658B2D12CDEC875D5BCF61B7D59863F9F89"),
    ("3230818732", "521751078096CB44D44D706DE2600E952BEB48F31525007016A55C7720B354AF"),
    ("3230825776", "9D89323FCCE17EBF5C9A217DD474851E46665C594A665A35CEC691033558FB3A"),
    ("3230886172", "E416DE69AB5CA7EB717154DC7907CE47BF7C38D55463C678E6BD4ADAC1F62DE6"),
    ("3230887197", "2606E756FB8CDBA45085406DCA726822DEBFE524470F3E719226306D6F5EF391"),
    ("3230902631", "E14D16569F9FEC51C97EC4D194EA63CC6017953B04E039285876DFEC81709281"),
    ("3230903269", "4B600EFF6D11736053586F279BDC891747262005401A1F15BAD65560B59A58B3"),
    ("3230903713", "12A5E87AB51782E499703625B48F2CB891DB4100061E07C2705780C705DBBDF5"),
    ("3230904258", "7889315AF4D9ED29E43290E4677B862B0ABB20601FBD3B00C58A48ECC575FE98"),
    ("3230904757", "53C663317159A2AF0BBD103A107FBB026FFE1F0A71C90641FCBC4514A9152B6F"),
    ("3230905305", "4E258DE9970D2C24792FC9B86EEF691C6C22F304F083B2C3EF98FFA173F5306A"),
    ("3230905780", "855F2AFA7FC378D23F616F65172B13C51D3D6CD5E444B5E20DBE"
),
    ("3185773108", "00E709A9E9DA3493BD6404115812F501B32290A6C0AE7DD42570377E02D4E84C"),
    ("3185783475", "8E24FBF432C11431C4E9E64E6134A5344EAA8EA284EB0C40B5C69D3214591433"),
    ("3185780804", "A4DCBA8B4A79BE7A42EA6B983E0166B10273C4DEF91296831B570ED62AFA24A7"),
    ("3185769946", "B8118B2281216B83244207225F241EBDBC281CB1DF7D0581432882DC9C856526"),
    ("3185766621", "0AB2605AE87E44EB4C48245588ABA3F29FE2346078E37907F2BAF37B30F744AD"),
    ("3185763642", "13C96233F9441C9A97810B2B2EDF1603FB1EC96AB0747E00EA7810B52CAE3736"),
    ("3185760911", "D9913481D521935416EFCDF76ED6CC8BACBE8ED8224E0FBC27BB6D0D7A31F3C8"),
    ("3185757655", "4A619233870117FFC80C68A3C419F5F100D0A8F70D3107AD3125F3860F08C61F"),
    ("3185754187", "7B24E9B4F34B3B064C13483A595B5B80BD760539CD5636C4CBB46D3001B1E8D0"),
    ("3162151475", "6715BFE2E726FE24DCE976ABA00FFC016A6208E0734746B12F3260F0181DDAEE"),
    ("3162155728", "0DB9FE43E204233A76350FDE740792BCA1A272B006A56CFA78A02B3A93AFAF2B"),
    ("3162337732", "B679F20D7DC7B2F7F4B7EB90DEA7B29A1E93FE8612E75CA9D49CD3C1E5959158"),
    ("3163263237", "DDAB5759BB38BEBE74C077640CF41D6F5A3B3AD7E470078FA7006A1959FDEF13"),
    ("3163271594", "5D7C275C69BDD5E1F366ACBF403238B9B04B50570A408CAE6871EC1D5DFA060F"),
    ("3163279744", "6AEED0078288FA9151A09C670473ABAC543F42162DB63CA6A087DB3AE4BCA370"),
    ("3163288564", "D880897E952D30C81CB92E3A8F1620E50A6CD7081D17DB425C647A1592404CCE"),
    ("3179489376", "C416929F87FC5217072B7B053D9D50C38FD4BFD0217A7397C2F1077A42A1BB73"),
    ("3185719323", "5646752D284A753F11D405E61CDFDB41AAE2A042CB889047BD7E19D78E38418C"),
    ("3185754187", "7B24E9B4F34B3B064C13483A595B5B80BD760539CD5636C4CBB46D3001B1E8D0"),
    ("3185757655", "4A619233870117FFC80C68A3C419F5F100D0A8F70D3107AD3125F3860F08C61F"),
    ("3185760911", "D9913481D521935416EFCDF76ED6CC8BACBE8ED8224E0FBC27BB6D0D7A31F3C8"),
    ("3185763642", "13C96233F9441C9A97810B2B2EDF1603FB1EC96AB0747E00EA7810B52CAE3736"),
    ("3185766621", "0AB2605AE87E44EB4C48245588ABA3F29FE2346078E37907F2BAF37B30F744AD"),
    ("3185769946", "B8118B2281216B83244207225F241EBDBC281CB1DF7D0581432882DC9C856526"),
    ("3185773108", "00E709A9E9DA3493BD6404115812F501B32290A6C0AE7DD42570377E02D4E84C"),
    ("3185780804", "A4DCBA8B4A79BE7A42EA6B983E0166B10273C4DEF91296831B570ED62AFA24A7"),
    ("3185783475", "8E24FBF432C11431C4E9E64E6134A5344EAA8EA284EB0C40B5C69D3214591433"),
]

INFO_TOKENS = [
    ("3811592035", "94076E2447C524E18B4CAA27A62526C95230DD7995B35F782E4AB09481AFCC80"),
]
# تعريف البوت
bot = telebot.TeleBot("8194942576:AAFTpIUDW_2nN3z4VSXZwykOfG8M91dMf08")  # استبدل YOUR_BOT_TOKEN بتوكن البوت الخاص بك

# تعريف المتغيرات
user_tasks = {}  # لتخزين مهام المستخدم

# وظيفة لإنشاء JWT
def get_jwt(uid, pw):
    api_url = f"https://get-jwt-neon.vercel.app/GeneRate-Jwt?Uid={uid}&Pw={pw}"
    response = requests.get(api_url)
    token_match = re.search(r"ToKen : (\S+)", response.text)
    if token_match:
        return token_match.group(1)
    else:
        return None

# وظيفة لتشفير الـ ID
def Encrypt_ID(x):
    x = int(x)
    dec = ['80', '81', '82', '83', '84', '85', '86', '87', '88', '89', '8a', '8b', '8c', '8d', '8e', '8f', '90', '91', '92', '93', '94', '95', '96', '97', '98', '99', '9a', '9b', '9c', '9d', '9e', '9f', 'a0', 'a1', 'a2', 'a3', 'a4', 'a5', 'a6', 'a7', 'a8', 'a9', 'aa', 'ab', 'ac', 'ad', 'ae', 'af', 'b0', 'b1', 'b2', 'b3', 'b4', 'b5', 'b6', 'b7', 'b8', 'b9', 'ba', 'bb', 'bc', 'bd', 'be', 'bf', 'c0', 'c1', 'c2', 'c3', 'c4', 'c5', 'c6', 'c7', 'c8', 'c9', 'ca', 'cb', 'cc', 'cd', 'ce', 'cf', 'd0', 'd1', 'd2', 'd3', 'd4', 'd5', 'd6', 'd7', 'd8', 'd9', 'da', 'db', 'dc', 'dd', 'de', 'df', 'e0', 'e1', 'e2', 'e3', 'e4', 'e5', 'e6', 'e7', 'e8', 'e9', 'ea', 'eb', 'ec', 'ed', 'ee', 'ef', 'f0', 'f1', 'f2', 'f3', 'f4', 'f5', 'f6', 'f7', 'f8', 'f9', 'fa', 'fb', 'fc', 'fd', 'fe', 'ff']
    xxx = ['1', '01', '02', '03', '04', '05', '06', '07', '08', '09', '0a', '0b', '0c', '0d', '0e', '0f', '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '1a', '1b', '1c', '1d', '1e', '1f', '20', '21', '22', '23', '24', '25', '26', '27', '28', '29', '2a', '2b', '2c', '2d', '2e', '2f', '30', '31', '32', '33', '34', '35', '36', '37', '38', '39', '3a', '3b', '3c', '3d', '3e', '3f', '40', '41', '42', '43', '44', '45', '46', '47', '48', '49', '4a', '4b', '4c', '4d', '4e', '4f', '50', '51', '52', '53', '54', '55', '56', '57', '58', '59', '5a', '5b', '5c', '5d', '5e', '5f', '60', '61', '62', '63', '64', '65', '66', '67', '68', '69', '6a', '6b', '6c', '6d', '6e', '6f', '70', '71', '72', '73', '74', '75', '76', '77', '78', '79', '7a', '7b', '7c', '7d', '7e', '7f']
    x = x / 128
    if x > 128:
        x = x / 128
        if x > 128:
            x = x / 128
            if x > 128:
                x = x / 128
                strx = int(x)
                y = (x - int(strx)) * 128
                stry = str(int(y))
                z = (y - int(stry)) * 128
                strz = str(int(z))
                n = (z - int(strz)) * 128
                strn = str(int(n))
                m = (n - int(strn)) * 128
                return dec[int(m)] + dec[int(n)] + dec[int(z)] + dec[int(y)] + xxx[int(x)]
            else:
                strx = int(x)
                y = (x - int(strx)) * 128
                stry = str(int(y))
                z = (y - int(stry)) * 128
                strz = str(int(z))
                n = (z - int(strz)) * 128
                strn = str(int(n))
                return dec[int(n)] + dec[int(z)] + dec[int(y)] + xxx[int(x)]

# وظيفة لفك تشفير API
def decrypt_api(cipher_text):
    key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
    iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plain_text = unpad(cipher.decrypt(bytes.fromhex(cipher_text)), AES.block_size)
    return plain_text.hex()

# وظيفة لتشفير API
def encrypt_api(plain_text):
    plain_text = bytes.fromhex(plain_text)
    key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
    iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    cipher_text = cipher.encrypt(pad(plain_text, AES.block_size))
    return cipher_text.hex()

# وظيفة لتحليل النتائج
def parse_results(parsed_results):
    result_dict = {}
    for result in parsed_results:
        field_data = {}
        field_data['wire_type'] = result.wire_type
        if result.wire_type == "varint":
            field_data['data'] = result.data
            result_dict[result.field] = field_data
        elif result.wire_type == "string":
            field_data['data'] = result.data
            result_dict[result.field] = field_data
        elif result.wire_type == 'length_delimited':
            field_data["data"] = parse_results(result.data.results)
            result_dict[result.field] = field_data
    return result_dict

# وظيفة للحصول على معلومات الغرفة
def get_available_room(input_text):
    parsed_results = Parser().parse(input_text)
    parsed_results_objects = parsed_results
    parsed_results_dict = parse_results(parsed_results_objects)
    json_data = json.dumps(parsed_results_dict)
    return json_data

# وظيفة لإخفاء النص
def antidetection(var):
    var = str(var)
    result = ""
    for l in var:
        result = result + "ِ" + l
    return result

# وظيفة للحصول على معلومات اللاعب
def Get_player_information(uid, token):
    data = bytes.fromhex(encrypt_api(f"08{Encrypt_ID(uid)}1007"))
    url = "https://clientbp.common.ggbluefox.com/GetPlayerPersonalShow"
    headers = {
        'X-Unity-Version': '2018.4.11f1',
        'ReleaseVersion': 'OB48',
        'Content-Type': 'application/x-www-form-urlencoded',
        'X-GA': 'v1 1',
        'Authorization': f'Bearer {token}',
        'Content-Length': '16',
        'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 7.1.2; ASUS_Z01QD Build/QKQ1.190825.002)',
        'Host': 'clientbp.ggblueshark.com',
        'Connection': 'Keep-Alive',
        'Accept-Encoding': 'gzip'
    }
    session = requests.Session()
    response = session.post(url, headers=headers, data=data, verify=False)
    if response.status_code == 200:
        hex_response = binascii.hexlify(response.content).decode('utf-8')
        json_result = get_available_room(hex_response)
        parsed_data = json.loads(json_result)
        NoClan = False
        try:
            player_id = str(parsed_data["1"]["data"]["1"]["data"])
            player_likes = parsed_data["1"]["data"]["21"]["data"]
            player_name = parsed_data["1"]["data"]["3"]["data"]
            player_server = parsed_data["1"]["data"]["5"]["data"]
            player_bio = parsed_data["9"]["data"]["9"]["data"]
            player_level = parsed_data["1"]["data"]["6"]["data"]
            account_date = parsed_data["1"]["data"]["44"]["data"]
            account_date = datetime.fromtimestamp(account_date)
            booya_pass_level = parsed_data["1"]["data"]["18"]["data"]
            try:
                animal_name = parsed_data["8"]["data"]["2"]["data"]
            except:
                animal_name = " - No Animal Name !"
            try:
                clan_id = parsed_data["6"]["data"]["1"]["data"]
                clan_name = parsed_data["6"]["data"]["2"]["data"]
                clan_leader = parsed_data["6"]["data"]["3"]["data"]
                clan_level = parsed_data["6"]["data"]["4"]["data"]
                clan_members_num = parsed_data["6"]["data"]["6"]["data"]
                clan_leader_name = parsed_data["7"]["data"]["3"]["data"]
                clan_leader_level = parsed_data["7"]["data"]["6"]["data"]
                clan_leader_booya_pass_level = parsed_data["7"]["data"]["18"]["data"]
                clan_leader_likes = parsed_data["7"]["data"]["21"]["data"]
                clan_leader_account_date = parsed_data["7"]["data"]["44"]["data"]
                clan_leader_account_date = datetime.fromtimestamp(clan_leader_account_date)
            except:
                NoClan = True
            if NoClan:
                info_string = f'''- Done Get Info Of Player Id : {uid}
[1] - ProFile Info :
> Name : {player_name}
> Id : {uid}
> Likes : {player_likes}
> Levl : {player_level}
> Server : {player_server}
> Bio : {player_bio}
> Booyah Pass Levl : {booya_pass_level}
> Animal Name : {animal_name}
> Create In : {account_date}

[!] - No Clan Info !

Dev : XAZ | @XAZ'''
            else:
                info_string = f'''- Done Get Info Of Player Id : {uid}

[1] - ProFile Info :
> Name : {player_name}
> Id : {uid}
> Likes : {player_likes}
> Levl : {player_level}
> Server : {player_server}
> Bio : {player_bio}
> Booyah Pass Levl : {booya_pass_level}
> Create In : {account_date}

[2] - Animal Info :
> Animal Name : {animal_name}

[3] - Clan Info :
> Clan Name : {clan_name}
> Clan Id : {clan_id}
> Clan Levl : {clan_level}
> Clan Members Num : {clan_members_num}
> Clan Leader : {clan_leader}
> Leader Name : {clan_leader_name}
> Leader Id : {antidetection(clan_leader)}
> Leader Likes : {clan_leader_likes}
> Leader Levl : {clan_leader_level}
> Leader Booyah Pass Levl : {clan_leader_booya_pass_level}
> Leader Acc Create It : {clan_leader_account_date}

- Dev : @pro.antiban'''
            return info_string
        except Exception as e:
            return f' - No Info For Id : {uid}'
    elif response.status_code == 400 or 401:
        return f' - Failed to get info for Id : {uid}'

# وظيفة لإرسال طلبات الصداقة
def Add_Fr(id, Tok):
    url = 'https://clientbp.common.ggbluefox.com/RequestAddingFriend'
    headers = {
        'X-Unity-Version': '2018.4.11f1',
        'ReleaseVersion': 'OB48',
        'Content-Type': 'application/x-www-form-urlencoded',
        'X-GA': 'v1 1',
        'Authorization': f'Bearer {Tok}',
        'Content-Length': '16',
        'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 7.1.2; ASUS_Z01QD Build/QKQ1.190825.002)',
        'Host': 'clientbp.ggblueshark.com',
        'Connection': 'Keep-Alive',
        'Accept-Encoding': 'gzip'
    }
    data = bytes.fromhex(encrypt_api(f'08a7c4839f1e10{Encrypt_ID(id)}1801'))
    response = requests.post(url, headers=headers, data=data, verify=False)
    
    if response.status_code == 400 and 'BR_FRIEND_NOT_SAME_REGION' in response.text:
        return f'Id : {id} Not In Same Region !'
    elif response.status_code == 200:
        return f'Good Response Done Send To Id : {id}!'
    elif 'BR_FRIEND_MAX_REQUEST' in response.text:
        return f'Id : {id} Reached Max Requests !'
    elif 'BR_FRIEND_ALREADY_SENT_REQUEST' in response.text:
        return f'Token Already Sent Requests To Id : {id}!'
    else:
        return response.text

# وظيفة للإعجاب
def like(token, id):
    url = 'https://202.81.99.18/LikeProfile'
    headers = {
        'X-Unity-Version': '2018.4.11f1',
        'ReleaseVersion': 'OB46',
        'Content-Type': 'application/x-www-form-urlencoded',
        'X-GA': 'v1 1',
        'Authorization': f'Bearer {token}',
        'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 7.1.2; ASUS_Z01QD Build/QKQ1.190825.002)',
        'Connection': 'Keep-Alive',
        'Accept-Encoding': 'gzip'
    }
    data = bytes.fromhex(encrypt_api(f'08{Encrypt_ID(id)}12024d45'))    
    response = requests.post(url, headers=headers, data=data, verify=False)
    return response.status_code == 200

# وظيفة للسبام
def spam(id):
    responses = []
    with ThreadPoolExecutor(max_workers=200) as executor:
        futures = [executor.submit(Add_Fr, id, get_jwt(uid, pw)) for uid, pw in SPAM_TOKENS]
        for future in futures:
            response = future.result()
            responses.append(response)
    return responses

# وظيفة للإعجابات
def send_likes(id):
    responses = []
    selected_tokens = random.sample(LIKE_TOKENS, min(200, len(LIKE_TOKENS)))
    with ThreadPoolExecutor(max_workers=200) as executor:
        futures = [executor.submit(like, get_jwt(uid, pw), id) for uid, pw in selected_tokens]
        for future in futures:
            success = future.result()
            responses.append(f"Like to {id}: {'Success' if success else 'Failed'}")
    return responses

# أمر /start
@bot.message_handler(commands=['start'])
def start(message):
    bot.reply_to(message, "مرحبًا! استخدم الأوامر التالية:\n"
                          "/spam <id> - لإرسال طلبات إضافة صديق.\n"
                          "/like <id> - لإرسال طلبات الإعجاب.\n"
                          "/info <id> - لجلب معلومات اللاعب.\n"
                          "/help - لعرض قائمة الأوامر.")

# أمر /help
@bot.message_handler(commands=['help'])
def help(message):
    bot.reply_to(message, "قائمة الأوامر المتاحة:\n"
                          "/spam <id> - لإرسال طلبات إضافة صديق.\n"
                          "/like <id> - لإرسال طلبات الإعجاب.\n"
                          "/info <id> - لجلب معلومات اللاعب.\n"
                          "/help - لعرض قائمة الأوامر.")

# أمر /spam
@bot.message_handler(commands=['spam'])
def handle_spam(message):
    id = message.text.split()[1] if len(message.text.split()) > 1 else None
    if id:
        responses = spam(id)
        bot.reply_to(message, "\n".join(responses))
    else:
        bot.reply_to(message, " - No Id ! ")

# أمر /like
@bot.message_handler(commands=['like'])
def handle_like(message):
    id = message.text.split()[1] if len(message.text.split()) > 1 else None
    if id:
        responses = send_likes(id)
        bot.reply_to(message, f"Done likes {id}")
    else:
        bot.reply_to(message, " - No Id ! ")

# أمر /info
@bot.message_handler(commands=['info'])
def handle_info(message):
    uid = message.text.split()[1] if len(message.text.split()) > 1 else None
    if uid:
        token = get_jwt(INFO_TOKENS[0][0], INFO_TOKENS[0][1])
        if token:
            info = Get_player_information(uid, token)
            bot.reply_to(message, info)
        else:
            bot.reply_to(message, " - Failed to get token !")
    else:
        bot.reply_to(message, " - No Id ! ")

# تشغيل البوت
bot.polling()