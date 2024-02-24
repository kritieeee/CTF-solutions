# MoneyBinder writeup

## Description
sirstealsalott has crossed the limit this time!He's captured MarioBank! Our intelligence has informed us that him and his team have been chatting on social media but the police has been unable to intercept their chats.  

## Solution

we look for sirstealsalott on different socials which lead us to the specific following twitter(X) account 


![ss1](https://github.com/kritieeee/CTF-solutions/blob/main/MoneyBinder/images-MoneyBinder/Screenshot%202024-02-21%20233833.png)

When we go to his liked tweets we find the following suspicious tweets:



![tw1](https://github.com/kritieeee/CTF-solutions/blob/main/MoneyBinder/images-MoneyBinder/Screenshot%202024-02-21%20233850.png)



![tw2](https://github.com/kritieeee/CTF-solutions/blob/main/MoneyBinder/images-MoneyBinder/Screenshot%202024-02-21%20233906.png)



The answer to katiereads' tweet is somehting called _Domain Generated Algorithms_  you can read about them [here](https://bluecatnetworks.com/blog/among-cyber-attack-techniques-what-is-a-dga/ )



When we look into `dimentiotheevil` account we find another couple of tweets


//tag image 
![dtetwt](https://github.com/kritieeee/CTF-solutions/blob/main/MoneyBinder/images-MoneyBinder/Screenshot%202024-02-21%20235416.png)

The tweets are clearly in Base64 so when we convert them we get the following texts 

`Try the tags on the bot you dummy`

`pastebins are the literal best!nobodys gonna get us here!`

`https://pastebin.com/0Ekmm4w1`

However the hashtags have no meaning..yet.
When we visit the pastebin link we find the following c code.



```
#include<stdio.h>
#include<stdlib.h>
#include<inttypes.h>

uint32_t generate_key(uint32_t);
char* generate_hashtag(uint32_t, uint32_t, uint32_t, uint32_t);

int main() {
	uint32_t initial_seed = 0;
	uint32_t key = generate_key(initial_seed);
	uint32_t year = 2024;
    for(uint32_t month = 2; month < 5; month++) {
        for(uint32_t day = 1; day < 32; day++) {
            char* hashtag = generate_hashtag(key, day, month, year);
            printf("%" PRIu32 "/%" PRIu32 "/2024: #%s\n", day, month, hashtag);
            free(hashtag);
        }
    }
	return 0;
}

char* generate_hashtag(uint32_t key, uint32_t day, uint32_t month, uint32_t year) {
    /* Generating new_key */
    uint32_t new_key = (((key * 0x10624DD3) >> 6) * 0xFFFFFC18) + key;

    /* Current day */
    uint32_t day_key = (day << 0x10) ^ day;
    if(day_key <= 1) {
        day_key = day << 0x18;
    }

    /* Current month */
    uint32_t month_key = (month << 0x10) ^ month;
    if(month_key <= 7) {
        month_key = month << 0x18;
        if(month_key <= 7) {
            month_key = ~month_key;
        }
    }

    /* Current year */
    uint32_t year_key = ((year + new_key) << 0x10) ^ (year + new_key);
    if(year_key <= 0xF) {
        year_key = ((year + new_key) << 0x18);
    }

    /* String length */
    uint32_t string_length = (((day_key ^ ((year_key ^ 8 * year_key ^ ((day_key ^ ((month_key ^ 4 * month_key) >> 6)) >> 8)) >> 5)) >> 6) & 3) + 0xC;

    /* Generating the name */
    uint32_t index = 0;
    char* servername = calloc(string_length+1, sizeof(char));
    servername[string_length] = '\x00';
    do {
        day_key = (day_key >> 0x13) ^ ((day_key >> 6) ^ (day_key << 0xC)) & 0x1FFF ^ (day_key << 0xC);
        month_key = ((month_key ^ 4 * month_key) >> 0x19) ^ 0x10 * (month_key & 0xFFFFFFF8);
        year_key = ((year_key ^ 8 * year_key) >> 0xB) ^((year_key & 0xFFFFFFF0) << 0x11);
        index++;
        servername[index-1] = (day_key ^ month_key ^ year_key) % 0x19 + 'a';
    } while(index < string_length);

    return servername;
}

uint32_t generate_key(uint32_t seed) {
    /* Stage 2: Generating the array of seeds */
    uint32_t seed_array[624];
    seed_array[0] = seed;
    for(int i = 1; i < 624; i++) {
        uint32_t previous_seed = seed_array[i - 1];
        uint32_t current_seed = (((previous_seed >> 0x1E) ^ previous_seed) * 0x6c078964) + i;
        seed_array[i] = current_seed;
    }
    
    /* Stage 3: Processing the array of seeds */
    int i = 0;
    while(i < 0xE3) {
        uint32_t seed_a = seed_array[i];
        uint32_t seed_b = seed_array[i + 1];
        uint32_t temp_a = (seed_a ^ seed_b) & 0x7FFFFFFF;
        i++;
        temp_a = (temp_a ^ seed_a) & 1;
        uint32_t consta[] = {0, 0x9908B0DF};
        temp_a = ((temp_a >> 1) ^ consta[0+(temp_a & 1)]) ^ seed_array[0x18C+i];

        seed_array[i - 1] = temp_a;
    }

    /* Stage 4: Computing the DWORD value */
    uint32_t temp_b = seed_array[1];
    temp_b = ((((temp_b >> 0xB) ^ temp_b) & 0xFF3A58AD) << 0x7) ^ (temp_b >> 0xB) ^ temp_b;
    uint32_t temp_c = ((temp_b & 0xFFFFDF8C) << 0xF) ^ temp_b;
    uint32_t key = temp_c ^ (temp_c >> 0x12);

    return key;
}
```




On running the following pastebin in an online editor or VS code, we get the following results  

```
1/2/2024: #potgymgtpyvdgu
2/2/2024: #eymjknmlatixnc
3/2/2024: #wyvmbvdxgqsxsi
4/2/2024: #ketrbawxndamec
5/2/2024: #dedurindyvhfte
6/2/2024: #rovxdjtjnhvtqm
7/2/2024: #kofbtrkvvmcigi
8/2/2024: #damwccbryikdsfu
9/2/2024: #vbaattxmnfurnal
10/2/2024: #kkrpcovrrnfoknb
11/2/2024: #dlfstgsfjxqhfos
12/2/2024: #qpvluxixtuvhvrn
13/2/2024: #jqjompfskackbiq
14/2/2024: #xabeukdmsyobnqv
15/2/2024: #qbohmcaamrvisna
16/2/2024: #gbhoiavinbxu
17/2/2024: #ybqryimnwljy
18/2/2024: #njbumcowujtc
19/2/2024: #gjkxdkfjbgec
20/2/2024: #tqkewcywjnpj
21/2/2024: #mqthnkpcugwc
22/2/2024: #byekberwkwni
23/2/2024: #tynnrmijsctw
24/2/2024: #mmjicxhlgwpjt
25/2/2024: #fnwltpegutaxo
26/2/2024: #tugbedxdmfidi
27/2/2024: #mvtevuuqeptvd
28/2/2024: #acmxqakwphdog
29/2/2024: #sdabirhrgmjrl
30/2/2024: #hkjqsfbapqxau
31/2/2024: #alwtkwxnjjfha
1/3/2024: #ofpfpgkeqnepxk
2/3/2024: #dpeytdqwbynkdy
3/3/2024: #vpncllhihebkkf
4/3/2024: #jnpqqtbnximwtf
5/3/2024: #cnyticrrjjqplh
6/3/2024: #qxnnmyxyxniegw
7/3/2024: #jxwqehokgblsxs
8/3/2024: #cqihsmqcaopskck
9/3/2024: #urvkjenxotdhdwn
10/3/2024: #jbjqmulcsskecdy
11/3/2024: #ccwtdmiqklywued
12/3/2024: #pyrvlixmeaiuncx
13/3/2024: #iafycauiunlxqso
14/3/2024: #wjsffqsbdfboftx
15/3/2024: #pkgivippwgfviqp
16/3/2024: #frdnxtatdgpk
17/3/2024: #xrmqpcqxmyeo
18/3/2024: #maskvrsikplr
19/3/2024: #facnnajtquyr
20/3/2024: #sagdmvdmitgw
21/3/2024: #lapgeetqtukp
22/3/2024: #aivaktvmjcev
23/3/2024: #sifdccmxrphk
24/3/2024: #ldfssiwvvchvl
25/3/2024: #eesvjatrkhuke
26/3/2024: #slxcojnnclapa
27/3/2024: #lmlffbkcteois
28/3/2024: #yliihkalontyx
29/3/2024: #rmvlxcwhfbwcb
30/3/2024: #gtbrdlqoovokm
31/3/2024: #yuoutdndiwsrp
1/4/2024: #rktpdgvfhywefe
2/4/2024: #ggisphovpnqilk
3/4/2024: #ygrvhpfqxxtuyp
4/4/2024: #mwntullffgijgx
5/4/2024: #fwwwmtcsoliony
6/4/2024: #tslayuuxfsemag
7/4/2024: #msudqdlslldnhb
8/4/2024: #fvvrgmddvisruly
9/4/2024: #xwjuweapmsvsxhp
10/4/2024: #mrwkiylkounywrf
11/4/2024: #fsknyqipirreatw
12/4/2024: #siyypajnsoeejjb
13/4/2024: #ljmcgrgahhdtgbe
14/4/2024: #aearrmrjrcwtlgj
15/4/2024: #sfnuieoojhwnien
16/4/2024: #iwhunmnsrtgp
17/4/2024: #bwqxfuegdqkg
18/4/2024: #pqwbposayccs
19/4/2024: #iqgehwjuhmff
20/4/2024: #vjedsgrlpxxm
21/4/2024: #ojngkoiyydxr
22/4/2024: #ddtjuiweqfvh
23/4/2024: #vddmmqnywxui
24/4/2024: #oisaiblerxxeu
25/4/2024: #hjgdysiqiibfx
26/4/2024: #vclsigpoxhqtc
27/4/2024: #odyvyxmtreuyf
28/4/2024: #cupinuptdelrm
29/4/2024: #uvdlemmgrwkhj
30/4/2024: #joibnatpdmgyt
31/4/2024: #cpveerquurgsq
```
There is also a hint in the comments section that says that the dates are irrelevant 
![hint](https://github.com/kritieeee/CTF-solutions/blob/main/MoneyBinder/images-MoneyBinder/Screenshot%202024-02-24%20135142.png)


Now, when we look through this list, we notice that some hashes match the hastags in the previous posts. For example, dimentiotheevil has used the hashtag  _#ddtjuiweqfvh_ and _#kofbtrkvvmcigi_ in his posts. Therefore, it is clear that the heist team is communicating through these hashtags.
We can now write a python script that autosearches these hashtags. However , these will not yeild a result on twitter directly as they are relatively new and do not have enough posts. Thus we will use a tool that helps us look at Hahtag Analytics.There are many such tools available on the internet for free such as [BrandMentions](https://brandmentions.com/hashtag-tracker/) or [Hashtagify](https://hashtagify.me/hashtag/smm) but the name of the challenge is Money _Binder_ which implied that one must use [TweetBinder](https://www.tweetbinder.com/)



On searching the hashtags manually(or writing a python script to do so,as the case may be), we find the additional following tweets which when decoded, yield the following tweets.  
![twt1](https://github.com/kritieeee/CTF-solutions/blob/main/MoneyBinder/images-MoneyBinder/Screenshot%202024-02-24%20152625.png)
![twt2](https://github.com/kritieeee/CTF-solutions/blob/main/MoneyBinder/images-MoneyBinder/Screenshot%202024-02-24%20152634.png)
![twt3](https://github.com/kritieeee/CTF-solutions/blob/main/MoneyBinder/images-MoneyBinder/Screenshot%202024-02-24%20152705.png)

`hehe they  are such dummies we are talking on a public network `

`failure is the key to success`

`everything you need is right here http://t.me/antiwariobot`

Using the above hints we go to the telegram bot that is linked (now offline)
and _Try the tags on the bot you dummy_ when we specifically try the tag #vjedsgrlpxxm on the bot we get the following output

![bot1](https://github.com/kritieeee/CTF-solutions/blob/main/MoneyBinder/images-MoneyBinder/Screenshot%202024-02-24%20154711.png)


when we open the file with notepad (as txt) we get the flag 
![flag](https://github.com/kritieeee/CTF-solutions/blob/main/MoneyBinder/images-MoneyBinder/Screenshot%202024-02-24%20154822.png)//insert notepad 



Flag : *BITSCTF{5541C0MMUN1C4710N1N73rrUP73D}*
