// Coinmode HTML/JS Helper object
// Version 3.10  20170127 - Adding sharing options
// Version 3.11  20170131 - Moving Login/Create pages to seperate items
// Version 3.12  20170201 - Modified images to be embedded to work with PlayCanvas
// Version 3.13  20170207 - Added QR code to topup from
// Version 3.14  20170216 - Reworked login order.  Round creation can now be charged (Fix ampersand on share)
// Version 3.15  20170216 - Bug fix for joining existing round
// Version 3.16  20170217 - Improved sharing so links are one url with previews
// Version 3.17  20170218 - Renamed session start/stop functions
// Version 3.18  20170218 - Flag if new rounds can have empty passwords.  Support for showing only public games, not locked ones.

// Last updated: 20170303

// TODOs
// Allow this to be opened in an external window! window.open(href, windowname, 'width=400,height=200,scrollbars=yes'); 

/* Methods
setup( callback(err, array_info ) - Called once when the game initialises and allows the user to login and select a round to join if it wasn't specified in the params.
	{		
		display_name:"bob",
		round_id:17, 
		session_token:"st_2iuDb2kAvzhC"
	}

session_start - Called when there is no game server to invoke session/start automatically.
show_panel_start - Will show the starting page if the params.no_start_screen is not set to true.
session_stop - Call to submit results for this session.  Only required if a client only game otherwise game server should call Coinmode session/stop for security
show_summary() - Shows the scores of the round so far

*/

// For local debugging only
var debug_session_token = null;
var debug_language = null;//"ja"; // Useful to force swapping to another language rather than user settings.


/*
var params=
{
	coinmode_api_server:"api.coinmode.com", 		// The server to send all the API requests to
	game_id: "33", 									// This is the game we are looking to play.  This is required for getting the play_token phase or creating new rounds
	[uuid_or_email]: "password0@radforth.com",		// [Optional] This is the default user to obtain a playtoken with.  It is used if a playtoken wasn't specified.
	[play_token]:"st_PQnD54nPaG2g" 					// [Optional] Use a playtoken as the voucher to obtain the session token for playing a game.  A playtoken is given by a user on the coinmode portal clicking to play this game.  A play token is like a login token but can only be used on a number of API calls and is restricted.
	[session_token]: "st_324849734895",				// [Development only] If launched from Coinmode website it will allow the game to be started via a session token.  This is to play one round of this particular game only for a given player.
	[login_token]: "cm_jkl345hkj34", 				// [Development only] This is not to be used in commercial games.  It has full access to a users account so not to be accepted on release builds
XX	request_permissions : 							// When asking a user to obtain a playtoken, these are the permissions requested to play the game.   This is so that the client can provide which optional permissions are requested for a playtoken
		"permission_charge_to_play,permission_phone,permission_charge_iap"
	call_session_start_from_client : false,			// If a single player game we can get this browser to invoke the session has started.  When doing multiplayer games it is best the server calls /session/start so it starts all players at the same time and can refund if there is an error.
	testnet : true									// If testnet coins should be used (Only effects the purchase button redirect)
	skip_start_screen : true, 						// This jumps straight into the game rather than showing the 'Play!' screen
	allow_topup_page: true, 						// If the user requires more funds to play, show the topup page

	auto_create_new_round_if_none_found : true, 	// If there were no rounds found automatically jump to the create a new round?  It requires the game to allow users to create new rounds from the coinmode admin panel.
	show_locked_rounds: true, // Default true, If the user requires more funds to play, show the topup page
	newround_passphrase_allow_user_entered : false; // If true it will allow the user to enter a passphrase on the 'create round' stage. Default is false and a random one is created each time so can only be joined by sharing invites.
	newround_allow_empty_passphrase : true,			// If a blank passphrase can be used (i.e. a public game), default false.
XX	newround_allow_public_rounds : false; 			// If true, you can create a public round anyone can see
	
	show_share_link_page : true, 					// If the share link page is shown after the new round is created
	shareoptions : {
		// "email" : false, // Disable sharing
		// "facebook" : false, // Disable sharing
		// "reddit" : false, // Disable sharing
		// "twitter" : false, // Disable sharing
		// "linkedin" : false, // Disable sharing
		// "google" : false, // Disable sharing
		// "pinterest" : false, // Disable sharing
		// "whatsapp" : false, // Disable sharing
		// "sms : false, // Disable sharing
	}	
}
*/



/*
 A JavaScript implementation of the SHA family of hashes, as
 defined in FIPS PUB 180-4 and FIPS PUB 202, as well as the corresponding
 HMAC implementation as defined in FIPS PUB 198a

 Copyright Brian Turek 2008-2016
 Distributed under the BSD License
 See http://caligatio.github.com/jsSHA/ for more information

 Several functions taken from Paul Johnston
*/
'use strict';(function(I){function w(c,a,d){var k=0,b=[],g=0,f,n,h,e,m,q,y,p,l=!1,t=[],r=[],u,z=!1;d=d||{};f=d.encoding||"UTF8";u=d.numRounds||1;if(u!==parseInt(u,10)||1>u)throw Error("numRounds must a integer >= 1");if(0===c.lastIndexOf("SHA-",0))if(q=function(b,a){return A(b,a,c)},y=function(b,a,k,f){var g,e;if("SHA-224"===c||"SHA-256"===c)g=(a+65>>>9<<4)+15,e=16;else throw Error("Unexpected error in SHA-2 implementation");for(;b.length<=g;)b.push(0);b[a>>>5]|=128<<24-a%32;a=a+k;b[g]=a&4294967295;
b[g-1]=a/4294967296|0;k=b.length;for(a=0;a<k;a+=e)f=A(b.slice(a,a+e),f,c);if("SHA-224"===c)b=[f[0],f[1],f[2],f[3],f[4],f[5],f[6]];else if("SHA-256"===c)b=f;else throw Error("Unexpected error in SHA-2 implementation");return b},p=function(b){return b.slice()},"SHA-224"===c)m=512,e=224;else if("SHA-256"===c)m=512,e=256;else throw Error("Chosen SHA variant is not supported");else throw Error("Chosen SHA variant is not supported");h=B(a,f);n=x(c);this.setHMACKey=function(b,a,g){var e;if(!0===l)throw Error("HMAC key already set");
if(!0===z)throw Error("Cannot set HMAC key after calling update");f=(g||{}).encoding||"UTF8";a=B(a,f)(b);b=a.binLen;a=a.value;e=m>>>3;g=e/4-1;if(e<b/8){for(a=y(a,b,0,x(c));a.length<=g;)a.push(0);a[g]&=4294967040}else if(e>b/8){for(;a.length<=g;)a.push(0);a[g]&=4294967040}for(b=0;b<=g;b+=1)t[b]=a[b]^909522486,r[b]=a[b]^1549556828;n=q(t,n);k=m;l=!0};this.update=function(a){var c,f,e,d=0,p=m>>>5;c=h(a,b,g);a=c.binLen;f=c.value;c=a>>>5;for(e=0;e<c;e+=p)d+m<=a&&(n=q(f.slice(e,e+p),n),d+=m);k+=d;b=f.slice(d>>>
5);g=a%m;z=!0};this.getHash=function(a,f){var d,h,m,q;if(!0===l)throw Error("Cannot call getHash after setting HMAC key");m=C(f);switch(a){case "HEX":d=function(a){return D(a,e,m)};break;case "B64":d=function(a){return E(a,e,m)};break;case "BYTES":d=function(a){return F(a,e)};break;case "ARRAYBUFFER":try{h=new ArrayBuffer(0)}catch(v){throw Error("ARRAYBUFFER not supported by this environment");}d=function(a){return G(a,e)};break;default:throw Error("format must be HEX, B64, BYTES, or ARRAYBUFFER");
}q=y(b.slice(),g,k,p(n));for(h=1;h<u;h+=1)q=y(q,e,0,x(c));return d(q)};this.getHMAC=function(a,f){var d,h,t,u;if(!1===l)throw Error("Cannot call getHMAC without first setting HMAC key");t=C(f);switch(a){case "HEX":d=function(a){return D(a,e,t)};break;case "B64":d=function(a){return E(a,e,t)};break;case "BYTES":d=function(a){return F(a,e)};break;case "ARRAYBUFFER":try{d=new ArrayBuffer(0)}catch(v){throw Error("ARRAYBUFFER not supported by this environment");}d=function(a){return G(a,e)};break;default:throw Error("outputFormat must be HEX, B64, BYTES, or ARRAYBUFFER");
}h=y(b.slice(),g,k,p(n));u=q(r,x(c));u=y(h,e,m,u);return d(u)}}function l(){}function D(c,a,d){var k="";a/=8;var b,g;for(b=0;b<a;b+=1)g=c[b>>>2]>>>8*(3+b%4*-1),k+="0123456789abcdef".charAt(g>>>4&15)+"0123456789abcdef".charAt(g&15);return d.outputUpper?k.toUpperCase():k}function E(c,a,d){var k="",b=a/8,g,f,n;for(g=0;g<b;g+=3)for(f=g+1<b?c[g+1>>>2]:0,n=g+2<b?c[g+2>>>2]:0,n=(c[g>>>2]>>>8*(3+g%4*-1)&255)<<16|(f>>>8*(3+(g+1)%4*-1)&255)<<8|n>>>8*(3+(g+2)%4*-1)&255,f=0;4>f;f+=1)8*g+6*f<=a?k+="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".charAt(n>>>
6*(3-f)&63):k+=d.b64Pad;return k}function F(c,a){var d="",k=a/8,b,g;for(b=0;b<k;b+=1)g=c[b>>>2]>>>8*(3+b%4*-1)&255,d+=String.fromCharCode(g);return d}function G(c,a){var d=a/8,k,b=new ArrayBuffer(d);for(k=0;k<d;k+=1)b[k]=c[k>>>2]>>>8*(3+k%4*-1)&255;return b}function C(c){var a={outputUpper:!1,b64Pad:"=",shakeLen:-1};c=c||{};a.outputUpper=c.outputUpper||!1;!0===c.hasOwnProperty("b64Pad")&&(a.b64Pad=c.b64Pad);if("boolean"!==typeof a.outputUpper)throw Error("Invalid outputUpper formatting option");if("string"!==
typeof a.b64Pad)throw Error("Invalid b64Pad formatting option");return a}function B(c,a){var d;switch(a){case "UTF8":case "UTF16BE":case "UTF16LE":break;default:throw Error("encoding must be UTF8, UTF16BE, or UTF16LE");}switch(c){case "HEX":d=function(a,b,c){var f=a.length,d,h,e,m,q;if(0!==f%2)throw Error("String of HEX type must be in byte increments");b=b||[0];c=c||0;q=c>>>3;for(d=0;d<f;d+=2){h=parseInt(a.substr(d,2),16);if(isNaN(h))throw Error("String of HEX type contains invalid characters");
m=(d>>>1)+q;for(e=m>>>2;b.length<=e;)b.push(0);b[e]|=h<<8*(3+m%4*-1)}return{value:b,binLen:4*f+c}};break;case "TEXT":d=function(c,b,d){var f,n,h=0,e,m,q,l,p,r;b=b||[0];d=d||0;q=d>>>3;if("UTF8"===a)for(r=3,e=0;e<c.length;e+=1)for(f=c.charCodeAt(e),n=[],128>f?n.push(f):2048>f?(n.push(192|f>>>6),n.push(128|f&63)):55296>f||57344<=f?n.push(224|f>>>12,128|f>>>6&63,128|f&63):(e+=1,f=65536+((f&1023)<<10|c.charCodeAt(e)&1023),n.push(240|f>>>18,128|f>>>12&63,128|f>>>6&63,128|f&63)),m=0;m<n.length;m+=1){p=h+
q;for(l=p>>>2;b.length<=l;)b.push(0);b[l]|=n[m]<<8*(r+p%4*-1);h+=1}else if("UTF16BE"===a||"UTF16LE"===a)for(r=2,e=0;e<c.length;e+=1){f=c.charCodeAt(e);"UTF16LE"===a&&(m=f&255,f=m<<8|f>>>8);p=h+q;for(l=p>>>2;b.length<=l;)b.push(0);b[l]|=f<<8*(r+p%4*-1);h+=2}return{value:b,binLen:8*h+d}};break;case "B64":d=function(a,b,c){var f=0,d,h,e,m,q,l,p;if(-1===a.search(/^[a-zA-Z0-9=+\/]+$/))throw Error("Invalid character in base-64 string");h=a.indexOf("=");a=a.replace(/\=/g,"");if(-1!==h&&h<a.length)throw Error("Invalid '=' found in base-64 string");
b=b||[0];c=c||0;l=c>>>3;for(h=0;h<a.length;h+=4){q=a.substr(h,4);for(e=m=0;e<q.length;e+=1)d="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".indexOf(q[e]),m|=d<<18-6*e;for(e=0;e<q.length-1;e+=1){p=f+l;for(d=p>>>2;b.length<=d;)b.push(0);b[d]|=(m>>>16-8*e&255)<<8*(3+p%4*-1);f+=1}}return{value:b,binLen:8*f+c}};break;case "BYTES":d=function(a,b,c){var d,n,h,e,m;b=b||[0];c=c||0;h=c>>>3;for(n=0;n<a.length;n+=1)d=a.charCodeAt(n),m=n+h,e=m>>>2,b.length<=e&&b.push(0),b[e]|=d<<8*(3+m%4*-1);
return{value:b,binLen:8*a.length+c}};break;case "ARRAYBUFFER":try{d=new ArrayBuffer(0)}catch(k){throw Error("ARRAYBUFFER not supported by this environment");}d=function(a,b,c){var d,n,h,e;b=b||[0];c=c||0;n=c>>>3;for(d=0;d<a.byteLength;d+=1)e=d+n,h=e>>>2,b.length<=h&&b.push(0),b[h]|=a[d]<<8*(3+e%4*-1);return{value:b,binLen:8*a.byteLength+c}};break;default:throw Error("format must be HEX, TEXT, B64, BYTES, or ARRAYBUFFER");}return d}function r(c,a){return c>>>a|c<<32-a}function J(c,a,d){return c&a^
~c&d}function K(c,a,d){return c&a^c&d^a&d}function L(c){return r(c,2)^r(c,13)^r(c,22)}function M(c){return r(c,6)^r(c,11)^r(c,25)}function N(c){return r(c,7)^r(c,18)^c>>>3}function O(c){return r(c,17)^r(c,19)^c>>>10}function P(c,a){var d=(c&65535)+(a&65535);return((c>>>16)+(a>>>16)+(d>>>16)&65535)<<16|d&65535}function Q(c,a,d,k){var b=(c&65535)+(a&65535)+(d&65535)+(k&65535);return((c>>>16)+(a>>>16)+(d>>>16)+(k>>>16)+(b>>>16)&65535)<<16|b&65535}function R(c,a,d,k,b){var g=(c&65535)+(a&65535)+(d&65535)+
(k&65535)+(b&65535);return((c>>>16)+(a>>>16)+(d>>>16)+(k>>>16)+(b>>>16)+(g>>>16)&65535)<<16|g&65535}function x(c){var a=[],d;if(0===c.lastIndexOf("SHA-",0))switch(a=[3238371032,914150663,812702999,4144912697,4290775857,1750603025,1694076839,3204075428],d=[1779033703,3144134277,1013904242,2773480762,1359893119,2600822924,528734635,1541459225],c){case "SHA-224":break;case "SHA-256":a=d;break;case "SHA-384":a=[new l,new l,new l,new l,new l,new l,new l,new l];break;case "SHA-512":a=[new l,new l,new l,
new l,new l,new l,new l,new l];break;default:throw Error("Unknown SHA variant");}else throw Error("No SHA variants supported");return a}function A(c,a,d){var k,b,g,f,n,h,e,m,l,r,p,w,t,x,u,z,A,B,C,D,E,F,v=[],G;if("SHA-224"===d||"SHA-256"===d)r=64,w=1,F=Number,t=P,x=Q,u=R,z=N,A=O,B=L,C=M,E=K,D=J,G=H;else throw Error("Unexpected error in SHA-2 implementation");d=a[0];k=a[1];b=a[2];g=a[3];f=a[4];n=a[5];h=a[6];e=a[7];for(p=0;p<r;p+=1)16>p?(l=p*w,m=c.length<=l?0:c[l],l=c.length<=l+1?0:c[l+1],v[p]=new F(m,
l)):v[p]=x(A(v[p-2]),v[p-7],z(v[p-15]),v[p-16]),m=u(e,C(f),D(f,n,h),G[p],v[p]),l=t(B(d),E(d,k,b)),e=h,h=n,n=f,f=t(g,m),g=b,b=k,k=d,d=t(m,l);a[0]=t(d,a[0]);a[1]=t(k,a[1]);a[2]=t(b,a[2]);a[3]=t(g,a[3]);a[4]=t(f,a[4]);a[5]=t(n,a[5]);a[6]=t(h,a[6]);a[7]=t(e,a[7]);return a}var H;H=[1116352408,1899447441,3049323471,3921009573,961987163,1508970993,2453635748,2870763221,3624381080,310598401,607225278,1426881987,1925078388,2162078206,2614888103,3248222580,3835390401,4022224774,264347078,604807628,770255983,
1249150122,1555081692,1996064986,2554220882,2821834349,2952996808,3210313671,3336571891,3584528711,113926993,338241895,666307205,773529912,1294757372,1396182291,1695183700,1986661051,2177026350,2456956037,2730485921,2820302411,3259730800,3345764771,3516065817,3600352804,4094571909,275423344,430227734,506948616,659060556,883997877,958139571,1322822218,1537002063,1747873779,1955562222,2024104815,2227730452,2361852424,2428436474,2756734187,3204031479,3329325298];"function"===typeof define&&define.amd?
define(function(){return w}):"undefined"!==typeof exports?("undefined"!==typeof module&&module.exports&&(module.exports=w),exports=w):I.jsSHA=w})(this);


// QR Code generation
(function(r){r.fn.qrcode=function(h){var s;function u(a){this.mode=s;this.data=a}function o(a,c){this.typeNumber=a;this.errorCorrectLevel=c;this.modules=null;this.moduleCount=0;this.dataCache=null;this.dataList=[]}function q(a,c){if(void 0==a.length)throw Error(a.length+"/"+c);for(var d=0;d<a.length&&0==a[d];)d++;this.num=Array(a.length-d+c);for(var b=0;b<a.length-d;b++)this.num[b]=a[b+d]}function p(a,c){this.totalCount=a;this.dataCount=c}function t(){this.buffer=[];this.length=0}u.prototype={getLength:function(){return this.data.length},
write:function(a){for(var c=0;c<this.data.length;c++)a.put(this.data.charCodeAt(c),8)}};o.prototype={addData:function(a){this.dataList.push(new u(a));this.dataCache=null},isDark:function(a,c){if(0>a||this.moduleCount<=a||0>c||this.moduleCount<=c)throw Error(a+","+c);return this.modules[a][c]},getModuleCount:function(){return this.moduleCount},make:function(){if(1>this.typeNumber){for(var a=1,a=1;40>a;a++){for(var c=p.getRSBlocks(a,this.errorCorrectLevel),d=new t,b=0,e=0;e<c.length;e++)b+=c[e].dataCount;
for(e=0;e<this.dataList.length;e++)c=this.dataList[e],d.put(c.mode,4),d.put(c.getLength(),j.getLengthInBits(c.mode,a)),c.write(d);if(d.getLengthInBits()<=8*b)break}this.typeNumber=a}this.makeImpl(!1,this.getBestMaskPattern())},makeImpl:function(a,c){this.moduleCount=4*this.typeNumber+17;this.modules=Array(this.moduleCount);for(var d=0;d<this.moduleCount;d++){this.modules[d]=Array(this.moduleCount);for(var b=0;b<this.moduleCount;b++)this.modules[d][b]=null}this.setupPositionProbePattern(0,0);this.setupPositionProbePattern(this.moduleCount-
7,0);this.setupPositionProbePattern(0,this.moduleCount-7);this.setupPositionAdjustPattern();this.setupTimingPattern();this.setupTypeInfo(a,c);7<=this.typeNumber&&this.setupTypeNumber(a);null==this.dataCache&&(this.dataCache=o.createData(this.typeNumber,this.errorCorrectLevel,this.dataList));this.mapData(this.dataCache,c)},setupPositionProbePattern:function(a,c){for(var d=-1;7>=d;d++)if(!(-1>=a+d||this.moduleCount<=a+d))for(var b=-1;7>=b;b++)-1>=c+b||this.moduleCount<=c+b||(this.modules[a+d][c+b]=
0<=d&&6>=d&&(0==b||6==b)||0<=b&&6>=b&&(0==d||6==d)||2<=d&&4>=d&&2<=b&&4>=b?!0:!1)},getBestMaskPattern:function(){for(var a=0,c=0,d=0;8>d;d++){this.makeImpl(!0,d);var b=j.getLostPoint(this);if(0==d||a>b)a=b,c=d}return c},createMovieClip:function(a,c,d){a=a.createEmptyMovieClip(c,d);this.make();for(c=0;c<this.modules.length;c++)for(var d=1*c,b=0;b<this.modules[c].length;b++){var e=1*b;this.modules[c][b]&&(a.beginFill(0,100),a.moveTo(e,d),a.lineTo(e+1,d),a.lineTo(e+1,d+1),a.lineTo(e,d+1),a.endFill())}return a},
setupTimingPattern:function(){for(var a=8;a<this.moduleCount-8;a++)null==this.modules[a][6]&&(this.modules[a][6]=0==a%2);for(a=8;a<this.moduleCount-8;a++)null==this.modules[6][a]&&(this.modules[6][a]=0==a%2)},setupPositionAdjustPattern:function(){for(var a=j.getPatternPosition(this.typeNumber),c=0;c<a.length;c++)for(var d=0;d<a.length;d++){var b=a[c],e=a[d];if(null==this.modules[b][e])for(var f=-2;2>=f;f++)for(var i=-2;2>=i;i++)this.modules[b+f][e+i]=-2==f||2==f||-2==i||2==i||0==f&&0==i?!0:!1}},setupTypeNumber:function(a){for(var c=
j.getBCHTypeNumber(this.typeNumber),d=0;18>d;d++){var b=!a&&1==(c>>d&1);this.modules[Math.floor(d/3)][d%3+this.moduleCount-8-3]=b}for(d=0;18>d;d++)b=!a&&1==(c>>d&1),this.modules[d%3+this.moduleCount-8-3][Math.floor(d/3)]=b},setupTypeInfo:function(a,c){for(var d=j.getBCHTypeInfo(this.errorCorrectLevel<<3|c),b=0;15>b;b++){var e=!a&&1==(d>>b&1);6>b?this.modules[b][8]=e:8>b?this.modules[b+1][8]=e:this.modules[this.moduleCount-15+b][8]=e}for(b=0;15>b;b++)e=!a&&1==(d>>b&1),8>b?this.modules[8][this.moduleCount-
b-1]=e:9>b?this.modules[8][15-b-1+1]=e:this.modules[8][15-b-1]=e;this.modules[this.moduleCount-8][8]=!a},mapData:function(a,c){for(var d=-1,b=this.moduleCount-1,e=7,f=0,i=this.moduleCount-1;0<i;i-=2)for(6==i&&i--;;){for(var g=0;2>g;g++)if(null==this.modules[b][i-g]){var n=!1;f<a.length&&(n=1==(a[f]>>>e&1));j.getMask(c,b,i-g)&&(n=!n);this.modules[b][i-g]=n;e--; -1==e&&(f++,e=7)}b+=d;if(0>b||this.moduleCount<=b){b-=d;d=-d;break}}}};o.PAD0=236;o.PAD1=17;o.createData=function(a,c,d){for(var c=p.getRSBlocks(a,
c),b=new t,e=0;e<d.length;e++){var f=d[e];b.put(f.mode,4);b.put(f.getLength(),j.getLengthInBits(f.mode,a));f.write(b)}for(e=a=0;e<c.length;e++)a+=c[e].dataCount;if(b.getLengthInBits()>8*a)throw Error("code length overflow. ("+b.getLengthInBits()+">"+8*a+")");for(b.getLengthInBits()+4<=8*a&&b.put(0,4);0!=b.getLengthInBits()%8;)b.putBit(!1);for(;!(b.getLengthInBits()>=8*a);){b.put(o.PAD0,8);if(b.getLengthInBits()>=8*a)break;b.put(o.PAD1,8)}return o.createBytes(b,c)};o.createBytes=function(a,c){for(var d=
0,b=0,e=0,f=Array(c.length),i=Array(c.length),g=0;g<c.length;g++){var n=c[g].dataCount,h=c[g].totalCount-n,b=Math.max(b,n),e=Math.max(e,h);f[g]=Array(n);for(var k=0;k<f[g].length;k++)f[g][k]=255&a.buffer[k+d];d+=n;k=j.getErrorCorrectPolynomial(h);n=(new q(f[g],k.getLength()-1)).mod(k);i[g]=Array(k.getLength()-1);for(k=0;k<i[g].length;k++)h=k+n.getLength()-i[g].length,i[g][k]=0<=h?n.get(h):0}for(k=g=0;k<c.length;k++)g+=c[k].totalCount;d=Array(g);for(k=n=0;k<b;k++)for(g=0;g<c.length;g++)k<f[g].length&&
(d[n++]=f[g][k]);for(k=0;k<e;k++)for(g=0;g<c.length;g++)k<i[g].length&&(d[n++]=i[g][k]);return d};s=4;for(var j={PATTERN_POSITION_TABLE:[[],[6,18],[6,22],[6,26],[6,30],[6,34],[6,22,38],[6,24,42],[6,26,46],[6,28,50],[6,30,54],[6,32,58],[6,34,62],[6,26,46,66],[6,26,48,70],[6,26,50,74],[6,30,54,78],[6,30,56,82],[6,30,58,86],[6,34,62,90],[6,28,50,72,94],[6,26,50,74,98],[6,30,54,78,102],[6,28,54,80,106],[6,32,58,84,110],[6,30,58,86,114],[6,34,62,90,118],[6,26,50,74,98,122],[6,30,54,78,102,126],[6,26,52,
78,104,130],[6,30,56,82,108,134],[6,34,60,86,112,138],[6,30,58,86,114,142],[6,34,62,90,118,146],[6,30,54,78,102,126,150],[6,24,50,76,102,128,154],[6,28,54,80,106,132,158],[6,32,58,84,110,136,162],[6,26,54,82,110,138,166],[6,30,58,86,114,142,170]],G15:1335,G18:7973,G15_MASK:21522,getBCHTypeInfo:function(a){for(var c=a<<10;0<=j.getBCHDigit(c)-j.getBCHDigit(j.G15);)c^=j.G15<<j.getBCHDigit(c)-j.getBCHDigit(j.G15);return(a<<10|c)^j.G15_MASK},getBCHTypeNumber:function(a){for(var c=a<<12;0<=j.getBCHDigit(c)-
j.getBCHDigit(j.G18);)c^=j.G18<<j.getBCHDigit(c)-j.getBCHDigit(j.G18);return a<<12|c},getBCHDigit:function(a){for(var c=0;0!=a;)c++,a>>>=1;return c},getPatternPosition:function(a){return j.PATTERN_POSITION_TABLE[a-1]},getMask:function(a,c,d){switch(a){case 0:return 0==(c+d)%2;case 1:return 0==c%2;case 2:return 0==d%3;case 3:return 0==(c+d)%3;case 4:return 0==(Math.floor(c/2)+Math.floor(d/3))%2;case 5:return 0==c*d%2+c*d%3;case 6:return 0==(c*d%2+c*d%3)%2;case 7:return 0==(c*d%3+(c+d)%2)%2;default:throw Error("bad maskPattern:"+
a);}},getErrorCorrectPolynomial:function(a){for(var c=new q([1],0),d=0;d<a;d++)c=c.multiply(new q([1,l.gexp(d)],0));return c},getLengthInBits:function(a,c){if(1<=c&&10>c)switch(a){case 1:return 10;case 2:return 9;case s:return 8;case 8:return 8;default:throw Error("mode:"+a);}else if(27>c)switch(a){case 1:return 12;case 2:return 11;case s:return 16;case 8:return 10;default:throw Error("mode:"+a);}else if(41>c)switch(a){case 1:return 14;case 2:return 13;case s:return 16;case 8:return 12;default:throw Error("mode:"+
a);}else throw Error("type:"+c);},getLostPoint:function(a){for(var c=a.getModuleCount(),d=0,b=0;b<c;b++)for(var e=0;e<c;e++){for(var f=0,i=a.isDark(b,e),g=-1;1>=g;g++)if(!(0>b+g||c<=b+g))for(var h=-1;1>=h;h++)0>e+h||c<=e+h||0==g&&0==h||i==a.isDark(b+g,e+h)&&f++;5<f&&(d+=3+f-5)}for(b=0;b<c-1;b++)for(e=0;e<c-1;e++)if(f=0,a.isDark(b,e)&&f++,a.isDark(b+1,e)&&f++,a.isDark(b,e+1)&&f++,a.isDark(b+1,e+1)&&f++,0==f||4==f)d+=3;for(b=0;b<c;b++)for(e=0;e<c-6;e++)a.isDark(b,e)&&!a.isDark(b,e+1)&&a.isDark(b,e+
2)&&a.isDark(b,e+3)&&a.isDark(b,e+4)&&!a.isDark(b,e+5)&&a.isDark(b,e+6)&&(d+=40);for(e=0;e<c;e++)for(b=0;b<c-6;b++)a.isDark(b,e)&&!a.isDark(b+1,e)&&a.isDark(b+2,e)&&a.isDark(b+3,e)&&a.isDark(b+4,e)&&!a.isDark(b+5,e)&&a.isDark(b+6,e)&&(d+=40);for(e=f=0;e<c;e++)for(b=0;b<c;b++)a.isDark(b,e)&&f++;a=Math.abs(100*f/c/c-50)/5;return d+10*a}},l={glog:function(a){if(1>a)throw Error("glog("+a+")");return l.LOG_TABLE[a]},gexp:function(a){for(;0>a;)a+=255;for(;256<=a;)a-=255;return l.EXP_TABLE[a]},EXP_TABLE:Array(256),
LOG_TABLE:Array(256)},m=0;8>m;m++)l.EXP_TABLE[m]=1<<m;for(m=8;256>m;m++)l.EXP_TABLE[m]=l.EXP_TABLE[m-4]^l.EXP_TABLE[m-5]^l.EXP_TABLE[m-6]^l.EXP_TABLE[m-8];for(m=0;255>m;m++)l.LOG_TABLE[l.EXP_TABLE[m]]=m;q.prototype={get:function(a){return this.num[a]},getLength:function(){return this.num.length},multiply:function(a){for(var c=Array(this.getLength()+a.getLength()-1),d=0;d<this.getLength();d++)for(var b=0;b<a.getLength();b++)c[d+b]^=l.gexp(l.glog(this.get(d))+l.glog(a.get(b)));return new q(c,0)},mod:function(a){if(0>
this.getLength()-a.getLength())return this;for(var c=l.glog(this.get(0))-l.glog(a.get(0)),d=Array(this.getLength()),b=0;b<this.getLength();b++)d[b]=this.get(b);for(b=0;b<a.getLength();b++)d[b]^=l.gexp(l.glog(a.get(b))+c);return(new q(d,0)).mod(a)}};p.RS_BLOCK_TABLE=[[1,26,19],[1,26,16],[1,26,13],[1,26,9],[1,44,34],[1,44,28],[1,44,22],[1,44,16],[1,70,55],[1,70,44],[2,35,17],[2,35,13],[1,100,80],[2,50,32],[2,50,24],[4,25,9],[1,134,108],[2,67,43],[2,33,15,2,34,16],[2,33,11,2,34,12],[2,86,68],[4,43,27],
[4,43,19],[4,43,15],[2,98,78],[4,49,31],[2,32,14,4,33,15],[4,39,13,1,40,14],[2,121,97],[2,60,38,2,61,39],[4,40,18,2,41,19],[4,40,14,2,41,15],[2,146,116],[3,58,36,2,59,37],[4,36,16,4,37,17],[4,36,12,4,37,13],[2,86,68,2,87,69],[4,69,43,1,70,44],[6,43,19,2,44,20],[6,43,15,2,44,16],[4,101,81],[1,80,50,4,81,51],[4,50,22,4,51,23],[3,36,12,8,37,13],[2,116,92,2,117,93],[6,58,36,2,59,37],[4,46,20,6,47,21],[7,42,14,4,43,15],[4,133,107],[8,59,37,1,60,38],[8,44,20,4,45,21],[12,33,11,4,34,12],[3,145,115,1,146,
116],[4,64,40,5,65,41],[11,36,16,5,37,17],[11,36,12,5,37,13],[5,109,87,1,110,88],[5,65,41,5,66,42],[5,54,24,7,55,25],[11,36,12],[5,122,98,1,123,99],[7,73,45,3,74,46],[15,43,19,2,44,20],[3,45,15,13,46,16],[1,135,107,5,136,108],[10,74,46,1,75,47],[1,50,22,15,51,23],[2,42,14,17,43,15],[5,150,120,1,151,121],[9,69,43,4,70,44],[17,50,22,1,51,23],[2,42,14,19,43,15],[3,141,113,4,142,114],[3,70,44,11,71,45],[17,47,21,4,48,22],[9,39,13,16,40,14],[3,135,107,5,136,108],[3,67,41,13,68,42],[15,54,24,5,55,25],[15,
43,15,10,44,16],[4,144,116,4,145,117],[17,68,42],[17,50,22,6,51,23],[19,46,16,6,47,17],[2,139,111,7,140,112],[17,74,46],[7,54,24,16,55,25],[34,37,13],[4,151,121,5,152,122],[4,75,47,14,76,48],[11,54,24,14,55,25],[16,45,15,14,46,16],[6,147,117,4,148,118],[6,73,45,14,74,46],[11,54,24,16,55,25],[30,46,16,2,47,17],[8,132,106,4,133,107],[8,75,47,13,76,48],[7,54,24,22,55,25],[22,45,15,13,46,16],[10,142,114,2,143,115],[19,74,46,4,75,47],[28,50,22,6,51,23],[33,46,16,4,47,17],[8,152,122,4,153,123],[22,73,45,
3,74,46],[8,53,23,26,54,24],[12,45,15,28,46,16],[3,147,117,10,148,118],[3,73,45,23,74,46],[4,54,24,31,55,25],[11,45,15,31,46,16],[7,146,116,7,147,117],[21,73,45,7,74,46],[1,53,23,37,54,24],[19,45,15,26,46,16],[5,145,115,10,146,116],[19,75,47,10,76,48],[15,54,24,25,55,25],[23,45,15,25,46,16],[13,145,115,3,146,116],[2,74,46,29,75,47],[42,54,24,1,55,25],[23,45,15,28,46,16],[17,145,115],[10,74,46,23,75,47],[10,54,24,35,55,25],[19,45,15,35,46,16],[17,145,115,1,146,116],[14,74,46,21,75,47],[29,54,24,19,
55,25],[11,45,15,46,46,16],[13,145,115,6,146,116],[14,74,46,23,75,47],[44,54,24,7,55,25],[59,46,16,1,47,17],[12,151,121,7,152,122],[12,75,47,26,76,48],[39,54,24,14,55,25],[22,45,15,41,46,16],[6,151,121,14,152,122],[6,75,47,34,76,48],[46,54,24,10,55,25],[2,45,15,64,46,16],[17,152,122,4,153,123],[29,74,46,14,75,47],[49,54,24,10,55,25],[24,45,15,46,46,16],[4,152,122,18,153,123],[13,74,46,32,75,47],[48,54,24,14,55,25],[42,45,15,32,46,16],[20,147,117,4,148,118],[40,75,47,7,76,48],[43,54,24,22,55,25],[10,
45,15,67,46,16],[19,148,118,6,149,119],[18,75,47,31,76,48],[34,54,24,34,55,25],[20,45,15,61,46,16]];p.getRSBlocks=function(a,c){var d=p.getRsBlockTable(a,c);if(void 0==d)throw Error("bad rs block @ typeNumber:"+a+"/errorCorrectLevel:"+c);for(var b=d.length/3,e=[],f=0;f<b;f++)for(var h=d[3*f+0],g=d[3*f+1],j=d[3*f+2],l=0;l<h;l++)e.push(new p(g,j));return e};p.getRsBlockTable=function(a,c){switch(c){case 1:return p.RS_BLOCK_TABLE[4*(a-1)+0];case 0:return p.RS_BLOCK_TABLE[4*(a-1)+1];case 3:return p.RS_BLOCK_TABLE[4*
(a-1)+2];case 2:return p.RS_BLOCK_TABLE[4*(a-1)+3]}};t.prototype={get:function(a){return 1==(this.buffer[Math.floor(a/8)]>>>7-a%8&1)},put:function(a,c){for(var d=0;d<c;d++)this.putBit(1==(a>>>c-d-1&1))},getLengthInBits:function(){return this.length},putBit:function(a){var c=Math.floor(this.length/8);this.buffer.length<=c&&this.buffer.push(0);a&&(this.buffer[c]|=128>>>this.length%8);this.length++}};"string"===typeof h&&(h={text:h});h=r.extend({},{render:"canvas",width:256,height:256,typeNumber:-1,
correctLevel:2,background:"#ffffff",foreground:"#000000"},h);return this.each(function(){var a;if("canvas"==h.render){a=new o(h.typeNumber,h.correctLevel);a.addData(h.text);a.make();var c=document.createElement("canvas");c.width=h.width;c.height=h.height;for(var d=c.getContext("2d"),b=h.width/a.getModuleCount(),e=h.height/a.getModuleCount(),f=0;f<a.getModuleCount();f++)for(var i=0;i<a.getModuleCount();i++){d.fillStyle=a.isDark(f,i)?h.foreground:h.background;var g=Math.ceil((i+1)*b)-Math.floor(i*b),
j=Math.ceil((f+1)*b)-Math.floor(f*b);d.fillRect(Math.round(i*b),Math.round(f*e),g,j)}}else{a=new o(h.typeNumber,h.correctLevel);a.addData(h.text);a.make();c=r("<table></table>").css("width",h.width+"px").css("height",h.height+"px").css("border","0px").css("border-collapse","collapse").css("background-color",h.background);d=h.width/a.getModuleCount();b=h.height/a.getModuleCount();for(e=0;e<a.getModuleCount();e++){f=r("<tr></tr>").css("height",b+"px").appendTo(c);for(i=0;i<a.getModuleCount();i++)r("<td></td>").css("width",
d+"px").css("background-color",a.isDark(e,i)?h.foreground:h.background).appendTo(f)}}a=c;jQuery(a).appendTo(this)})}})(jQuery);


// Copy to clipboard https://github.com/ryanpcmcquen/cheval
// @license magnet:?xt=urn:btih:cf05388f2679ee054f2beb29a391d25f4e673ac3&dn=gpl-2.0.txt GPL-v2-or-later
/*! cheval v1.0.4 by ryanpcmcquen */
!function(){"use strict";var textClassName="text-to-copy",buttonClassName="js-copy-btn",sets={},regexBuilder=function(prefix){return new RegExp(prefix+"\\S*")};window.addEventListener("DOMContentLoaded",function(){var texts=Array.prototype.slice.call(document.querySelectorAll("[class*="+textClassName+"]")),buttons=Array.prototype.slice.call(document.querySelectorAll("[class*="+buttonClassName+"]")),classNameFinder=function(arr,regex,namePrefix){return arr.map(function(item){return!!item.className.match(regex)&&item.className.match(regex)[0].replace(namePrefix,"")}).sort()};sets.texts=classNameFinder(texts,regexBuilder(textClassName),textClassName),sets.buttons=classNameFinder(buttons,regexBuilder(buttonClassName),buttonClassName);var matches=sets.texts.map(function(ignore,index){return sets.texts[index].match(sets.buttons[index])}),throwErr=function(err){throw new Error(err)},iPhoneORiPod=!1,iPad=!1,oldSafari=!1,navAgent=window.navigator.userAgent;/^((?!chrome).)*safari/i.test(navAgent)&&!/^((?!chrome).)*[0-9][0-9](\.[0-9][0-9]?)?\ssafari/i.test(navAgent)&&(oldSafari=!0),navAgent.match(/iPhone|iPod/i)?iPhoneORiPod=!0:navAgent.match(/iPad/i)&&(iPad=!0);var cheval=function(btn,text){var copyBtn=document.querySelector(btn),setCopyBtnText=function(textToSet){copyBtn.textContent=textToSet};(iPhoneORiPod||iPad)&&oldSafari&&setCopyBtnText("Select text"),copyBtn?copyBtn.addEventListener("click",function(){var oldPosX=window.scrollX,oldPosY=window.scrollY,originalCopyItem=document.querySelector(text),dollyTheSheep=originalCopyItem.cloneNode(!0),copyItem=document.createElement("textarea");if(copyItem.style.opacity=0,copyItem.setAttribute("disabled",!0),copyItem.style.position="absolute",copyItem.value=dollyTheSheep.value||dollyTheSheep.textContent,document.body.appendChild(copyItem),copyItem){copyItem.focus(),copyItem.selectionStart=0,copyItem.selectionEnd=originalCopyItem.textContent.length;try{document.execCommand("copy"),setCopyBtnText(oldSafari?iPhoneORiPod?"Now tap 'Copy'":iPad?"Now tap the text, then 'Copy'":"Press Command + C to copy":"Copy again")}catch(ignore){setCopyBtnText("Please copy manually")}originalCopyItem.focus(),window.scrollTo(oldPosX,oldPosY),originalCopyItem.selectionStart=0,originalCopyItem.selectionEnd=originalCopyItem.textContent.length,copyItem.remove()}else throwErr("You don't have an element with the class: '"+textClassName+"'. Please check the cheval README.")}):throwErr("You don't have a <button> with the class: '"+buttonClassName+"'. Please check the cheval README.")};matches.map(function(i){cheval("."+buttonClassName+i,"."+textClassName+i)})})}();
// @license-end


// Generate random string
function random_string( length, chars ) 
{
    var result = '';
	var milliseconds = (new Date).getTime();
	// Create a new unique ID using a secure random function
	if( chars == null)
	{
		chars = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
	}
	
    for (var i = length; i > 0; --i)
	{
		var charindex = Math.floor(Math.random() * 65534) + Math.floor(milliseconds);
		charindex = charindex ^ 0xF7F3F1BEEF;
		if( charindex < 0 )
		{
			charindex = -charindex;
		}
		var modindex = charindex % chars.length;
		result += chars[ modindex ];
	}
    return result;
}

// Get the GET parameters on the URL
function get_url_params(index)
{
	var url = window.location.search;
	var queryString = url.split("?")[1];
	if( queryString != null )
	{
		var keyValuePairs = queryString.split("&");
		var keyValue;
		var params = {};
		keyValuePairs.forEach(function (pair)
			{
				keyValue = pair.split("=");
				params[keyValue[0]] = decodeURIComponent(keyValue[1]).replace("+", " ");
			}
		);
		return params[index];
	}
	else
	{
		return null;
	}
}

function dalert(msg)
{
	console.log(msg);
	alert(msg);
}



// Given an epoch time this will give the text such as "07:11 on Fri, 02 Jan"
function epoch_to_text(epoch)
{
	if( typeof( epoch ) == "string" )
	{
		epoch = parseInt( epoch );
	}
	var text_date = "";
	try
	{		
		var e = new Date(0); // The 0 there is the key, which sets the date to the epoch
		e.setUTCSeconds(epoch);
		text_date = e.toGMTString().substring(17, 22) + " on " + e.toGMTString().substring(0, 11);
	}
	catch(e)
	{
		text_date= "Exception Date:"+e;
	}
	return text_date;
}



// Detect if it's a mobile phone
function is_mobile()
{
	if (/Android|webOS|iPhone|iPad|iPod|BlackBerry|BB|PlayBook|IEMobile|Windows Phone|Kindle|Silk|Opera Mini/i.test(navigator.userAgent)) 
	{
		// Take the user to a different screen here.
		return true;
	}
	else
	{
		return false;
	}
}

function is_ios()
{
	var ua = navigator.userAgent.toLowerCase();
	if (ua.indexOf("iphone") > -1 || ua.indexOf("ipad") > -1) 
	{
		return true;
	} 
	else 
	{
		return false;
	}
}







// Translate text functions
function CoinModeTranslate()
{
}
CoinModeTranslate.m_language = "en";
CoinModeTranslate.ma_translations = 
{
	"Your existing CoinMode ID/Email:" : { fr : "Votre CoinMode existant / Email:", es : "Su CoinMode existente ID / Email:", zh:"您现有的CoinMode ID /电子邮件：", ko:"기존 CoinMode의 ID / 이메일:", ja:"既存のCoinModeのID/メール：", pl:"Istniejąca CoinMode ID / e-mail:", pt:"Istniejąca CoinMode ID / e-mail:", it:"Il tuo attuale CoinMode ID / e-mail:", cs:"Vaše stávající CoinMode ID / E-mail:", "ru":"Ваш существующий CoinMode ID / E-mail:", sv:"Din befintliga CoinMode ID / E-post:" },
	"No Players" : { fr : "Aucun joueur", es : "No hay jugadores", zh:"没有玩家", ko:"어떤 선수가 없습니다", ja:"いいえ選手はありません", pl:"polish", sr:"serbian", pt:"portugese", it:"Italian", cs:"Czech", "ru":"Russian", sv:"swedish" },
	"Cancel" : {"cs":"Zrušit","es":"Cancelar", "fr":"Annuler","it":"Annulla","ja":"キャンセル","ru":"Отмена","sv":"Annullera","zh":"取消"},
	"Play" : { fr : "Démarrer", es : "comienzo" },
	"New User" : { ja : "新しいユーザー" },
	"Login" : { ja : "ログイン" },
	"Next" : { ja : "次" },
	"Back" : { ja : "バック" },
	"Password" : { ja : "パスワード" },
	"Incorrect Password" : { ja : "不正なパスワード" },
	"Network connection error. Check your internet connection and try again" : {ja:"ネットワーク接続エラー"},
	"Click To Share Link" : { ja : "クリックしてリンクを共有する", zh:"点击分享链接" },
}



CoinModeTranslate.set_language = function( language_in )
{
	CoinModeTranslate.m_language = "en";
	if( language_in == null )
	{
		language_in = window.navigator.userLanguage || window.navigator.language;
		language_in = language_in.substring( 0,2 );
	}
	
	if( debug_language != null )
	{
		language_in = debug_language;
	}

	// http://www.w3schools.com/tags/ref_language_codes.asp
	CoinModeTranslate.m_language = language_in;
	
}



CoinModeTranslate.translate = function( text_in, language )
{
	var new_text = text_in;
	
	if( text_in == "" )
	{
		return "";
	}
	
	if( ( language == "" ) || ( language == null ) )
	{
		language = CoinModeTranslate.m_language;		
	}
	if( ( language == "" ) || ( language == "en" ) )
	{
		return text_in;
	}
	if( CoinModeTranslate.ma_translations[text_in] )
	{
		var textobj = CoinModeTranslate.ma_translations[text_in];
		if( textobj[language] != null )
		{
			new_text = textobj[language];
		}
		else
		{
			console.log("Missing a language for translation ("+language+") of:'"+text_in+"'");
			//debugger;
		}
	}
	else
	{	
		console.log("Missing translation of:'"+text_in+"'");
	}
	return new_text;
}









	
// As of 20160809
var coinmode_login_html = "\                                                                                              \
<!-- version 2.0 -->                                                                                                      \
<div id='coinmode_root'>                                                                                                  \
    <div ui-view='content'>\
		<div id='coinmode_spinner' class='sk-folding-cube'>\
		  <div class='sk-cube1 sk-cube'></div>\
		  <div class='sk-cube2 sk-cube'></div>\
		  <div class='sk-cube4 sk-cube'></div>\
		  <div class='sk-cube3 sk-cube'></div>\
		</div>\
    </div>\
	<div id='coinmode_background'>                                                                                        \
		<div id='coinmode_inner_panel' class='coinmode_box'>                                                              \
			<div id='coinmode_logged_in_as' class='coinmode_subbox'>                                                      \
			</div>                                                                                                        \
			<div id='coinmode_log_out' class='coinmode_subbox'>                                                           \
				Log out																									  \
			</div>                                                                                                        \
			<div class='coinmode_boxtitle_root'>                                                                          \
				<div id='coinmode_boxtitle_gameimage'>                                         \
					<img class='coinmode_image_game_icon' src='http://gatherhelp.com/coinmode_admin/main/files/pongfree_sr0gqfvu.png'>\
				</div>                                         \
				<img class='coinmode_with_image' src='data:image/png;base64,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'>\
				<div id='coinmode_boxtitle_text'>                                         \
				</div>                                                                                                    \
			</div>                                                                                                        \
			<div id='coinmode_subbox' class='coinmode_subbox'>                                                                                 \
			</div>                                                                                                        \
                                                                                                                          \
			<div id='coinmode_buttons_area'>                                                                              \
			</div>                                                                                                        \
			<div id='coinmode_errortext' class='coinmode_errortext'>                                                \
			</div>                                                                                                        \
		</div>                                                                                                            \
	</div>                                                                                                                \
</div>                                                                                                                    \
";





// on_initalised( err, array_details ) - on_start is called when CoinModeClient starts up successfully
// Call CoinModeClient's start(on_start) to begin the login process.
function CoinModeClient( params, on_initalised )
{
	var that = this;
	this.demo = true;
	this.params = params;
	this.when_logged_in = null;
	this.display_name = null;  // Set to the users display name when they login
	
	this._html_added = false;
	this._has_start_been_called = false;
	this._has_stop_been_called = false;
	this.uuid = "";
	this.m_coinmode_api_server = "https://api.coinmode.com";
	if( params['coinmode_api_server'] != null )
	{
		this.m_coinmode_api_server = params['coinmode_api_server'];
	}
	this.m_play_token = params['play_token'];
	this.m_session_token = params['session_token'];
	this.m_round_id = null;		// This stores the round_id the user is connecting to
	this.m_passphrase = "";
	this.m_is_new_user = true;
	this.m_coinmode_round_pot_fee = 0;
	this.m_currency_type = "bitcoin_test";
	
	
	if( this.params['game_id'] == null )
	{
		throw("Missing a game_id param. You must specify the game_id in the initialisation params.  Look at Coinmode.com developer portal for more information");
	}
	// TODO: Derive this from the database
//	if( this.params['game_name'] == null )
//	{
//		throw("Missing a game_name param. This is required for sharing feature");
//	}

	// If the developer has specified the round_id/passphrase explicitly in the params use this.  Otherwise check the URL GET params by default
	if(this.params['round_id'] == null)
	{
		// Set the defaults to attempt to join with
		this.m_attempt_to_join_round_id = get_url_params('round_id');
		this.m_attempt_to_join_passphrase = get_url_params('passphrase');
		this.m_attempt_to_join_passphrase = sanitise_passphrase( this.m_attempt_to_join_passphrase );
		
		console.log("Getting round_id and passphrase from the URL GET parameters");
		console.log("Found round_id:"+this.m_attempt_to_join_round_id);
		console.log("Found passphrase:"+this.m_attempt_to_join_passphrase);
	}
	else
	{
		this.m_attempt_to_join_round_id = this.params['round_id'];
		this.m_attempt_to_join_passphrase = this.params['passphrase'];
		console.log("Getting round_id and passphrase from the params array");
	}
	
	// Set the default language
	CoinModeTranslate.set_language();

	// register jQuery extension
	jQuery.extend(jQuery.expr[':'], {
		focusable: function (el, index, selector) {
			return $(el).is('a, button, :input, [tabindex]');
		}
	});

	// Auto focus next tabstop
	$(document).on('keydown', ':focusable', function (e) {
		if (e.which == 13) {
			e.preventDefault();
			// Get all focusable elements on the page
			var $canfocus = $(':focusable');
			var index = $canfocus.index(this) + 1;
			if (index >= $canfocus.length) index = 0;
			$canfocus.eq(index).focus();
		}
	});

	


	// Will prompt the user to log in if required
	this.setup = function( on_complete )
	{
		this.when_logged_in = on_complete;
		this.add_html(
			function()
			{
				if( ( that.m_play_token != "" ) && ( that.m_play_token != null ) )
				{
					// We have a play token already so just jump to the round selection page
					that.show_panel_rounds_if_necessary();
				}
				else
				{
					that.try_auto_login()
				}			
			}
		);
	}
	
	
	this.try_auto_login = function()
	{
		var uuid_or_email = this.get_last_client_id();

		if( uuid_or_email == "" ) 
		{
			this.show_panel_login_or_new_user();
		}
		else
		{
			// Set the m_uuid value to use in the final redirect to coinmode.
			that.m_uuid = uuid_or_email;
			
			this.show_panel_confirm_user();
		}
	}
	
	// This method has no UI displayed
	// Will prompt the user to log in if required
	// on_complete( error, session_info );
	this.session_start = function( on_complete )
	{
		// Make sure setup has been called
		if( !this.m_session_token )
		{
			return on_complete( "missing successful call to setup() that obtains the session token" );
		}
		
		if( this.params.call_session_start_from_client )
		{		
			// Now we need to register this session token as started.  This step will deduct the money from their account and enable the server features.
			this.api_call( "/games/round/session/start",
				{
					session_token		: that.m_session_token
				},
				function( error, session_info )
				{
					on_complete( error, session_info );
				}
			);
		}
		else
		{
			on_complete( null, { session_token : that.m_session_token} );
		}
		
		this._has_start_been_called = true;
	}
	
	
	
	// This method has no UI displayed and simply signals to coinmode the game client has completed.
	// on_complete( error, session_info );
	this.session_stop = function( results_from_client, on_complete )
	{
		// Make sure session_start has been called
		if( !this._has_start_been_called )
		{
			return on_complete( "missing successful call to session_start()" );
		}
		// Make sure setup has been called
		if( !this.m_session_token )
		{
			return on_complete( "missing successful call to setup() that obtains the session token" );
		}
		// Stop the session and save the results
		this.api_call( "/games/round/session/stop",
			{
				results_from_client	: results_from_client,
			},
			function( error, session_info )
			{				
				on_complete( error, session_info );
			}
		);
		this._has_stop_been_called = true;
		
	}
	
	
	
	// Returns the winning pot amount as returned by get_round_info.
	this.get_winning_pot = function()
	{
		return this.m_winning_pot;
	}
	
	
	
	// This displays a window to allow the user to add in review feedback.
	// on_complete( error, review_added ) - If error is null, everything worked successfully.  
	this.show_summary = function( on_complete )
	{
		console.log("SR: Showing summary");
		this.add_html(
			function()
			{
						
				panel_clear_all();
				
				panel_set_title( "Results for round:"+that.m_round_id );
				
						
				
				buttons_add( "Play Again", function()
					{
						spinner_show();
						buttons_disable();
						
						// TODO: This may be all that is needed but currently doing reload();
						// on_complete( error );

						location.reload();
					}
				);
						

				buttons_add( "Portal", function()
					{
						spinner_show();
						buttons_disable();
						
						// TODO:
						// Show Sign up
						debugger;
						window.location.replace("http://www.coinmode.com/intro.html?uuid="+that.m_uuid);				
					}
				);
						
						
						
				
				spinner_show();
				
				that.api_call( "/games/round/get_results",
					{
						round_id		: that.m_round_id,
						session_token	: that.m_session_token // Submit the session token to allow ther server respond to which was your session.
					},
					function( error, result_info )
					{
						spinner_hide();
						console.log("Got results:");
						console.log(result_info);
						
						var array_sessions = result_info['sessions'];
						
						var show_winnings = true;
												
						var result_type = "Score";
						if( show_winnings )
						{
							result_type = "Winnings";
						}
						var html_subbox =  "<div class='coinmode_table_header_text'>Name<span class='coinmode_table_header_text coinmode_summary_points'>"+result_type+"</span></div>";
						for( i = 0; i < array_sessions.length; i++ )
						{
							var session = array_sessions[i];
							var player_name = session['player_name'];
							
							if( player_name == null )
							{
								player_name = "New Player";
							}
							var status_text = session['status_text'];
							var score = session['score'];
							var is_this_player = false;
							if( that.m_session_token == session['session_token'] )
							{
								// This is YOU
								is_this_player = true;
							}								


							if( is_this_player )
							{
								classname = "coinmode_score_highlight_player";
							}
							else
							{
								classname = "coinmode_score_normal_player";								
							}
							//SR: TODO, MUST OBTAIN m_pot_total from get_result!
							if( show_winnings )
							{
								var paid_out = session['paid_out'];
								
								paid_out = 0;
								if( score > 0 )
								{
									paid_out = 7650; // SR: TODO!!! THIS ISNT REPORTING THE PAID OUT VALUE CORRECTLY YET SO HARDCODED
								}
								score = that.currency_format_with_btc_and_local( paid_out, m_currency_units);
							}
							
							
							html_subbox += "<div class='"+classname+"'>"+player_name+"<span class='coinmode_summary_points'>"+score+"</span></div>"
						}
						
						$('#coinmode_subbox').html( html_subbox );
						
					}
				);
			}
		);				
	}
	
	// This displays a window to allow the user to add in review feedback.
	// on_complete( error, review_added ) - If error is null, everything worked successfully.  
	this.show_won_for_new_player = function( on_complete )
	{
		console.log("SR: Showing summary");
		this.add_html(
			function()
			{
						
				panel_clear_all();
				
				// If they won
				panel_set_title( "You Won!"+this.m_round_id );
				

				buttons_add( "Donate", function()
					{
						spinner_show();
						buttons_disable();
						
						// TODO:
						// Show Sign up
						//window.location.replace("http://www.coinmode.com/intro.html?uuid="+this.m_uuid);				
					}
				);
						
						
				
				buttons_add( "Sign up", function()
					{
						spinner_show();
						buttons_disable();
						
						// TODO:
						// Show Sign up
						window.location.replace("http://www.coinmode.com/donate.html?uuid="+this.m_uuid);				
					}
				);
						
						
						
				
				spinner_show();
				
				that.api_call( "/games/round/get_results",
					{
						round_id		: that.m_round_id
					},
					function( error, result_info )
					{
						spinner_hide();
						console.log("Got results:");
						console.log(result_info);
						
						var array_sessions = result_info['sessions'];
						
						var html_subbox = "";
						for( i = 0; i < array_sessions.length; i++ )
						{
							var session = array_sessions[i];
							var player_name = session['display_name'];
							var status_text = session['status_text'];
							var score = session['score'];
							html_subbox += "<div>Player ID:"+player_name+"<span class='coinmode_summary_points'>"+score+"</span></div>"
						}
						
						$('#coinmode_subbox').html( "<div>Congratulations, you have earned some credits</div>To claim this click below to setup your account or click Donate and you can donate your funds to a charity" );
						
						on_complete( error );
					}
				);
			}
		);				
	}
	
	
	// This displays a window to allow the user to add in review feedback.
	// on_complete( error, review_added ) - If error is null, everything worked successfully.  
	this.show_review = function( on_complete )
	{
		// Make sure session_start has been called
		if( !this._has_stop_been_called )
		{
			//return on_complete( "missing successful call to session_stop()" );
		}
		// Make sure setup has been called
		if( !this.m_session_token )
		{
			//return on_complete( "missing successful call to setup() that obtains the session token" );
		}
		
		this.add_html(
			function()
			{
				that.show_panel_review( function( err )
				{
					if( that.m_is_new_user )
					{
						that.show_panel_complete_registration( function(err)
							{
								that.remove_html( function()
									{
										on_complete();
									}
								);
							}
						);
					}
					else
					{
						that.remove_html( function()
							{
								on_complete();
							}
						);
					}
				}
				);
			}
		);				
	}
	
	
	
	// If the user has logged in, return the display name, otherwise return the default or null.
	this.get_display_name = function( default_name )
	{
		var display_name = "";
		if( this['display_name'] != null )
		{
			display_name = this['display_name'];
		}
		else		
		{
			display_name = default_name;
		}
		return display_name;
	}
	
	






	
	// Adds the required HTML tags for login/authentication
	this.add_html = function( on_complete )
	{
		// Move to top
		window.scrollTo(0,0);		
		
		if( !this._html_added )
		{
			if( !params['no_add_html'] )
			{
				$(document.body).append(coinmode_login_html);
			}
			
			// Disable scrolling.
			this._fn_ontouchmoveoriginal = document.ontouchmove;
			document.ontouchmove = function (e) {
				e.preventDefault();
			}			
			
			//$(document.body).append('<div id="coinmode_root">Hello there, this is just added</div>');
			
			
			// Fade it in beautifully
			$('#coinmode_background').fadeIn(1000,		
				function()
				{
					that._html_added = true;
					// Setup buttons
					/*
					$('#coinmode_login_login').click( 	that.login_on_login );
					$('#coinmode_login_cancel').click( 	that.login_on_cancel );
					$('#coinmode_login_new').click( 	that.login_on_new );
					
					$('#coinmode_password_confirm').click( 	that.on_password_confirm );
					$('#coinmode_password_cancel').click( 	that.on_password_cancel );
					
					$('#coinmode_start_start').click( 	that.start_on_start );
					$('#coinmode_start_cancel').click( 	that.start_on_cancel );
			*/
					$('#coinmode_log_out').click( that.on_logout );
			
					if( on_complete != null )
					{
						on_complete();
					}
				}
			);
		}
		else
		{
			on_complete();
		}
	}
	
	this.on_logout = function()
	{
		that.set_last_client_id( null );
		that.set_last_display_name( null );
		that.show_panel_login_or_new_user();
	}
	
	// Removes the HTML frames used by Coinmode to log players in/out
	this.remove_html = function( on_complete )
	{
		if( this._html_added )
		{
			$('#coinmode_background').fadeOut( 200, function()
				{			
					$(document.body).remove('#coinmode_root');
					that._html_added = false;
					
					// Re-enable scrolling.
					document.ontouchmove = this._fn_ontouchmoveoriginal;
					/*function (e) 
					{
					  return true;
					}*/					
					
					if( on_complete != null )
					{
						on_complete();
					}
				}
			);
		}
		else
		{
			on_complete();
		}
	}

	
	
/*
	this.get_current_uuid = function( on_found_uuid )
	{
		// TODO: Get UUID locally?
		
		// Request my UUID from coinmode and it will return a list based on the IP address found.
		$.post(coinmode_server + "/players/get_uuid_for_ip",
			{
				from_client: "TODO"
			},
			function(data, status)
			{
				//alert("Data: " + data + "\nStatus: " + status);
				//on_found_uuid( null, data );
				on_found_uuid( null, data.uuid );
			}
		);	
	}
	
	*/
	
	
	
	// Helper method to call CoinMode APIs
	// on_complete( error_string, data );
	this.api_call = function( method_name, params, on_complete )
	{
		if( method_name.substring( 0, 1 ) != "/" )
		{
			alert( "api_call ("+method_name+") is missing leading / e.g. /rounds/list" );
			method_name = "/"+method_name;
		}
		var url = this.m_coinmode_api_server + method_name;
		console.log("Making API call to:"+url);
		console.log("Params");
		console.dir( params );
		$.post(url,
			params,
			function(data, status_response)
			{
				
				if( data != null )
				{
					if( data['status'] == "ok" )
					{
						return on_complete( null, data );
					}
					on_complete( "status error", data );					
				}
				on_complete( null, data );					
			}
		).fail(function(response) 
		{
			if( ( response.status == 0 ) && ( response.statusText == "error" ) )
			{
				return on_complete( { error:"Network connection error. Check your internet connection and try again" } );
			}
			try{
				console.log(response);
				console.log( "Error doing CoinMode API Request:"+method_name+" Error:" + response.responseJSON['error'] );
			}
			catch(e)
			{
				alert( "exception:"+e);
				on_complete( { error: "unknown. Dev to look at more"} );
			}
			try{
			console.log( "Error doing CoinMode API Request:"+method_name+" Error:" + response.responseJSON['error'] );
			on_complete( response.responseJSON );
			}
			catch(e)
			{
				alert( "exception:"+e);
				on_complete( { error: "unknown. Dev to look at more"} );
			}
		}
		);							
	};

	
	
	// Call this to remove all CoinMode HTML and begin the game
	this._start_game = function( err )
	{
		$('#coinmode_background').fadeOut(1000,		
			function()
			{
				that.remove_html( function()
					{					
						if( that.when_logged_in != null )
						{
							var array_details = 
							{
								display_name : that.m_display_name,
								round_id : that.m_round_id,
								session_token : that.m_session_token,								
							};
							
							that.when_logged_in( err, array_details );				
						}
					}
				);
			}
		);
	}
	
	
	
	function spinner_show()
	{
		$('#coinmode_spinner').fadeIn();
	}
	function spinner_hide()
	{
		$('#coinmode_spinner').hide();
	}
	

	
	
	// PANEL BUTTONS
	var g_button_id = 0;
	var g_disabled_buttons = false;
	
	
	
	// Removes all buttons from the coinmode_buttons_area
	function buttons_clear()
	{
		g_button_id = 0;
		g_disabled_buttons = false;
		$('#coinmode_buttons_area').html("");
	}
	
	
	
	// Adds a button to the coinmode_buttons_area
	function buttons_add( button_text, on_click, button_id, tabindex )
	{
		g_button_id = g_button_id + 1;
		if( button_id == null )
		{
			button_id = g_button_id;
		}
		button_translated_text = CoinModeTranslate.translate( button_text );
		var tab_html = "";
		if( tabindex != null )
		{
			tab_html = " tabindex='"+tabindex+"'";
		}
		
		var button_html = "<span id='coinmode_button_"+button_id+"' class='coinmode_color_title coinmode_button' "+tab_html+">"+button_translated_text+"</span>";

		$('#coinmode_buttons_area').append( button_html );
		$('#coinmode_button_'+button_id).click( function()
		{
			if( !g_disabled_buttons )
			{
				if( on_click != null )
				{
					on_click();
				}
			}
			else
			{
				console.log("Buttons are disabled");
			}
		} 
		);
		// Return the button ID
		return '#coinmode_button_'+button_id;
	}
	
	
	
	// Disable the coinmode buttons because we're waiting for some logic to complete for instance.
	function buttons_disable( ignore_cancel )
	{
		//$('#coinmode_buttons_area').hide();
		g_disabled_buttons = true;
		$('.coinmode_button').css('opacity', '0.3');
	}
	
	
	
	// This will allow the coinmode buttons to be tapped again.
	function buttons_enable()
	{
		g_disabled_buttons = false;
		$('.coinmode_button').css('opacity', '1.0');
		//$('coinmode_button').removeAttr("disabled");
		//$('#coinmode_buttons_area').show();
	}
	
	
	
	// display the error text, call with null or "" to clear
	function panel_error_show( error_text_in )
	{
		spinner_hide();
		
		if( error_text_in == null )
		{
			error_text = "";
		}
		else
		{
			error_text = error_text_in;
		}
		
		$('#coinmode_errortext').text( error_text );
		$('#coinmode_errortext').show();
		setTimeout( function(){$('#coinmode_errortext').fadeOut( 2000 );}, 8 * 1000 );
	}
	
	
	
	// Set the title in the coinmode dialogue box
	function panel_set_title(title_in)
	{
		var title = CoinModeTranslate.translate( title_in );
		$('#coinmode_boxtitle_text').text(title);
		if( title == "" )
		{
			$('#coinmode_boxtitle_text').hide();
		}
		else
		{
			$('#coinmode_boxtitle_text').fadeIn();
		}
	}
	
	function panel_error_clear()
	{
		panel_error_show("");
	}

	function panel_clear_all( keep_error_messages )
	{
		// Clear last screen
		buttons_clear();
		if( keep_error_messages != true )
		{
			panel_error_clear();
		}
		panel_set_title("");
		$('#coinmode_subbox').html("");
	}
	
	
	
	
	
	
	
	
	this.has_local_storage = (function() 
		{
		try {
			
			var checkitem = "testing";
			localStorage.setItem("testmod", checkitem);
			if( localStorage.getItem("testmod") != checkitem )
			{
				return false;
			}
			localStorage.removeItem("testmod");
			return true;
		} catch (exception) {
			return false;
		}
		}()
	);
	
	// Check if the browser is in incognito mode
	this.is_incognito = function( on_found )
	{
		var fs = window.RequestFileSystem || window.webkitRequestFileSystem;
		if (!fs)
		{
			console.log("check failed for incognito");
			on_found(false);
		}
		else
		{
			fs(window.TEMPORARY,
				100,
				function ()
				{
					on_found(false)
				},
					function ()
				{ // Yes incognito
					on_found(true)
				}
			);
		}
	}	
	
	// This will return a string, perhaps an "" string if nothing was found.
	this.get_last_client_id = function()
	{
		if( !this.has_local_storage )
		{
			alert("Local storage is not available. If you are in private browsing your browser if preventing this feature so your name will never be stored");
		}
		
		try
		{
			var last = localStorage.getItem("coinmode_uuid");
			if( ( last === undefined ) ||
				( last === "undefined" ) ||
				( last === null ) )
			{
				last = "";
			}
		}
		catch(e)
		{
			console.log("Exception reading id:"+e);
		}
		return last;
	}
	
	this.set_last_client_id = function( uuid )
	{
		if( !this.has_local_storage )
		{
			alert("Local storage is not available. If you are in private browsing your browser if preventing this feature so your name will never be stored");
		}
		try
		{
			if( uuid != null )
			{
				localStorage.setItem("coinmode_uuid", uuid);
			}
		}
		catch(e)
		{
			console.log("error while setting last client_id:"+e);
		}
	}
	
	// This will return a string, perhaps an "" string if nothing was found.
	var show_once = true;
	this.get_last_display_name = function()
	{
		if( !this.has_local_storage )
		{
			if( show_once )
			{
				show_once = false;
				alert("Local storage is not available. If you are in private browsing your browser if preventing this feature so your name will never be stored");
			}
		}
		
		try
		{
			var last = localStorage.getItem("coinmode_display_name");
			if( ( last === undefined ) ||
				( last === "undefined" ) ||
				( last === null ) )
			{
				last = "";
			}
		}
		catch(e)
		{
			console.log("Exception reading id:"+e);
		}
		return last;
	}
	
	this.set_last_display_name = function( display_name )
	{
		this.display_name = display_name;
									
		if( !this.has_local_storage )
		{
			alert("Local storage is not available. If you are in private browsing your browser if preventing this feature so your name will never be stored");
		}
		try
		{
			if( display_name != null )
			{
				localStorage.setItem("coinmode_display_name", display_name);
			}
			else
			{
				localStorage.removeItem("coinmode_display_name");
			}
		}
		catch(e)
		{
			console.log("error while setting last client_id:"+e);
		}
		
		// Make sure we show who's logged in
		that.update_loggged_in_name();
	}
	
	
	// This just stores a local version should the user log out they will still use the last currency type we knew they liked
	this.get_display_currency = function()
	{
		try
		{
			var last = localStorage.getItem("coinmode_display_currency");
			if( ( last === undefined ) ||
				( last === "undefined" ) ||
				( last === null ) )
			{
				last = "usd";
			}
		}
		catch(e)
		{
			console.log("Exception reading id:"+e);
		}
		return last;
	}
	
	// Set a local copy of the display currency the player wants to use.  This is obtained from the user preferences when obtaining a playtoken
	this.set_display_currency = function( display_currency )
	{
		that.api_call( "/players/wallet/set_display_currency",
			{
				play_token		: that.m_play_token,
				currency		: display_currency
			},
			function( error, result_info )
			{
			}
		);
	
		try
		{
			localStorage.setItem("coinmode_display_currency", display_currency);
		}
		catch(e)
		{
			console.log("error while setting last client_id:"+e);
		}
	}
	
	
	
	
	
	
	
	
	// ------------------------------ SCREENS ------------------------------------
	function coinmode_login_textchange()
	{
		var login_name = '#coinmode_button_'+'login';
		if( $('#coinmode_username_uuidfield').val().length > 5 )
		{
			$(login_name).css('opacity', '1.0');			
		}
		else
		{
			$(login_name).css('opacity', '0.3');			
		}
	}
	
	
	
	this.show_panel_confirm_user = function()
	{
		var uuid_or_email = this.get_last_client_id();		
		
		// Set the default language
		CoinModeTranslate.set_language();
		
		
		panel_clear_all();
		
		//panel_set_title( "" );
		
		// Check if this userid can login.
		that.update_loggged_in_name();
				
		buttons_add( "Play Game", function()
			{
				spinner_show();
				buttons_disable();

				that.m_is_new_user = false;
				that.show_round_info(uuid_or_email);
			}
		);
		buttons_enable();
	}
	
	this.update_loggged_in_name = function()
	{
		var pretext = "Logged in as ";
		var playername = that.get_last_display_name();
		$('#coinmode_log_out').show();
		if( playername == null )
		{
			pretext = "Not Logged In";
			playername = "";
			$('#coinmode_log_out').hide();
		}
		else if( playername == "" )
		{
			// Get the UUID#
			playername = that.get_last_client_id();
		
			if( playername.length > 14 )
			{
				pretext = "";
			}
		}
		$('#coinmode_logged_in_as').html(pretext+playername);
	}
	
	// Shows the login page and sets up the button clicks
	this.show_panel_login_or_new_user = function()
	{
		// Set the default language
		CoinModeTranslate.set_language();
		
		
		panel_clear_all();
		
		panel_set_title( "Login" );
		
		var html_subbox = "";
		$('#coinmode_subbox').html( html_subbox );
		
		buttons_add( "Cancel", function()
			{
				that._start_game( "User cancelled" );
			}
		);
		// Allow line break otherwise it exceeds limits
		$('#coinmode_buttons_area').append("<br/>");
		buttons_add( "Login", function()
			{
				that.show_panel_get_userid();
			}, 'login'
		);
		buttons_add( "New User", function()
			{					
				that.show_panel_new_name();
			}
		);
		buttons_enable();
	}
	
	
	
	// Shows the login page and sets up the button clicks
	this.show_panel_get_userid = function()
	{
		// Set the default language
		CoinModeTranslate.set_language();
		
		
		panel_clear_all();
		
		panel_set_title( "User UUID or Email" );		
		
		var uuid_or_email = that.params.uuid_or_email;
		if( ( uuid_or_email == "" ) ||
			( uuid_or_email == null ) ) 
		{
			// This will return a string, perhaps an empty string if nothing was found.
			uuid_or_email = this.get_last_client_id();
		}
		var html_subbox = "\
			<span id='coinmode_username_text' class='coinmode_field_description'>                                     \
				"+CoinModeTranslate.translate("Your existing CoinMode ID/Email:")+"                                   \
			</span>                                                                                                   \
			<span id='coinmode_username_input'>                                                                       \
				<input id='coinmode_username_uuidfield' name='uuid' class='coinmode_inputbox' value='"+uuid_or_email+"' tabindex='0'></input>   \
			</span>"
		$('#coinmode_subbox').html( html_subbox );
		$('#coinmode_username_uuidfield').change( coinmode_login_textchange );
		$('#coinmode_username_uuidfield').keyup( coinmode_login_textchange );
		
		buttons_add( "Back", function()
			{
				that.show_panel_login_or_new_user();
			}
		);
		buttons_add( "Login", function()
			{
				if( $('#coinmode_username_uuidfield').val().length > 5 )
				{
					spinner_show();
					buttons_disable();
					that.params.uuid_or_email = $('#coinmode_username_uuidfield').val();
					// Save this ID for future logins
					that.set_last_client_id( that.params.uuid_or_email );
					
					that.m_uuid = that.params.uuid_or_email;
					that.m_is_new_user = false;

					that.show_round_info(that.params.uuid_or_email);
				}
			}, 'login'
		);
		buttons_enable();
		// Disable login until it's valid
		coinmode_login_textchange();
	}
	
	// Shows the round information
	this.show_round_info = function(uuid_or_email)
	{
		// Set the default language
		CoinModeTranslate.set_language();
		
		
		panel_clear_all();
		
		panel_set_title( "" );		
		
		if( that.m_attempt_to_join_round_id )
		{		
			spinner_show();
			that.api_call( "/games/round/get_results",
				{
					round_id		: that.m_attempt_to_join_round_id
				},
				function( error, result_info )
				{
					spinner_hide();
					
					if( error )
					{
						alert( "Got error while getting round info. Please try again later." );
						debugger;
					}
					console.log("Got results:");
					console.log(result_info);
					var round_info = result_info['round_info'];
					var fee_total = round_info['fee_play_session'] + round_info['pot_contribution'];
					that.m_winning_pot = round_info['winning_pot'];
					that.m_pot_contribution = round_info['pot_contribution'];
					var game_name = round_info['game_name'];
					
					// Save the game name to be used in the sharing link URI
					that.m_game_name = round_info['game_name'];
					
					var round_name = round_info['round_name'];
					panel_set_title( "Round "+round_name );		
					var round_playable = "";
					var can_play = true;
					if( round_info['status_id'] == 3 )  // Completed
					{
						round_playable = "This round has already completed.";
					}
					else if( round_info['status_id'] == 7 )  // Completed
					{
						round_playable = "This round has already finished.";
						can_play = false;
					}
					else if( round_info['require_lock_to_start_round'] == 1 )
					{
						if( round_info['status_id'] == 2 )
						{
							round_playable = "This round has already started and can not be joined.";
							can_play = false;
						}
						else if( round_info['status_id'] != 1 )
						{
							round_playable = "This round is no longer playable. (status:"+round_info['status_id']+")";
							can_play = false;
						}
					}

					
					function display_payment_details ()
					{
						var html_subbox = "\
							<div class='coinmode_bitcoinaddress'> \
								"+game_name+" \
							</div>";
							
						html_subbox += "<div id='coinmode_fees'>\
							<div class='coinmode_errortext'>"+round_playable+"</div>";
							
						if( can_play )
						{
							if( fee_total > 0 )
							{
								html_subbox += "\
									<div>Total fee to join "+that.currency_format_with_btc_and_local(fee_total)+"</div> \
									<div class='coinmode_smallsubtletext'>Fee to join "+that.currency_format_with_btc_and_local(fee_total)+"</div> \
									<div class='coinmode_smallsubtletext'>Pot contribution"+that.currency_format_with_btc_and_local(fee_total)+"</div>";
							}
							else
							{
								html_subbox += "\
									<div class='coinmode_freetoplay'>This round is free to play!</div> \
									<div class='coinmode_smallsubtletext'>Fee to join "+that.currency_format_with_btc_and_local(fee_total)+"</div> \
									<div class='coinmode_smallsubtletext'>Pot contribution"+that.currency_format_with_btc_and_local(fee_total)+"</div>";
							}
						}
						html_subbox += "</div>";
							
						if( can_play )
						{
							if( that.m_winning_pot > 0 )
							{
								
								var local_currency_type = that.get_display_currency();
								var html_local = " <span class='coinmode_currency_local_all'>"+that.currency_format( that.m_winning_pot, local_currency_type, true )+"</span>";
								var html_btc = that.currency_format( that.m_winning_pot, "BTC", true );
								
								html_subbox += "\
								<div class='coinmode_reward_value'> \
									Winner Will Receive <div>"+html_local+"</div><div>"+html_btc+"</div> \
								</div>";
							}
							if( that.m_pot_contribution > 0 )
							{
								html_subbox += "\
								<div class='coinmode_bitcoinaddress'> \
									Each Player Contributes To The Pot:"+that.m_pot_contribution+" \
								</div>";
							}
						}
						
						$('#coinmode_subbox').html( html_subbox );
					}
					
					display_payment_details();
					$('#coinmode_fees').click( function()
						{
							change_default_currency_type();
							display_payment_details();
						}
					);

					buttons_add( "Next", function()
						{
							that._request_new_playtoken( uuid_or_email );
						}
					);
					buttons_enable();
		
				}
			);					
		}
		else
		{
			console.log("No m_attempt_to_join_round_id found so jumping straight to show rounds");
			that._request_new_playtoken( uuid_or_email );
			//that.show_panel_rounds_if_necessary();
			return;
		}	
		
		buttons_add( "Cancel", function()
			{
				that.show_panel_login_or_new_user();
			}
		);

		
	}
	
	// // NOT CURRENTLY USED
	// this._request_new_playtoken_and_show_rounds = function(uuid_or_email)
	// {
		// this._request_new_playtoken(uuid_or_email,
			// function( error )
			// {
				// if( error )
				// {
					// // There was an error on getting the new playtoken!
				// }
				// else
				// {
					// // All good so can now show the rounds
					// that.show_panel_rounds_if_necessary();
				// }
			// }
		// );
	// }
	
	this._request_new_playtoken = function(uuid_or_email, on_complete)
	{
		spinner_show();
		that.api_call( "/players/playtokens/request", 
			{
				player_uuid_or_email : uuid_or_email,
				game_id	: that.params.game_id,
				permissions : params.request_permissions
			},
			function(error, data)
			{
				spinner_hide();
				
				if( error )
				{
					var disp_error = error.error;							
					if( disp_error.indexOf( "No player found" ) >= 0 )
					{
						if( that.params.uuid_or_email.indexOf("@") > 0 )
						{
							disp_error = CoinModeTranslate.translate("No player found, have you verified this email address yet?");
						}
						else
						{
							disp_error = CoinModeTranslate.translate("No player found, please try again or select 'New User'");
						}
					}
					disp_error = CoinModeTranslate.translate(disp_error);
					panel_error_show(disp_error);
					alert("Error getting play token for this uuid:"+disp_error);
					buttons_enable();
				}
				else
				{
					if( ( data['language'] != "en" ) && 
						( data['language'] != "" ) )
					{
						console.log("About to set language from english to:"+data['language']);
						//alert("About to set language:"+data['language']);
					}
					
					// Set the display name that can be obtained by the game via client.get_display_name()
					that.set_last_display_name( data['display_name'] );
					
					CoinModeTranslate.set_language( data['language'] );
					
					if( data['display_currency'] != null )
					{
						change_default_currency_type( data['display_currency'] );
					}
					else
					{
						change_default_currency_type( "usd" );
					}
					
					//alert( "About to set m_uuid again");
					console.log(data);
					// Set the m_uuid if found here because it's better to have than their email address if they used that to login with.
					if( data['uuid'] != null )
					{
						that.m_uuid = data['uuid'];
					}
					that.m_play_token = data['playtoken_uuid'];
					// TODO: If it requires verification, ask for this information
					that._show_panel_playtoken_verify(data, function( err )
						{
							if( err == "back" )
							{
								alert( "Back pressed");								
								error = "back";
							}
							else
							{
								// Everything is ok, so can proceed
								that.show_panel_rounds_if_necessary();
							}
							
						}
					);
				}
				if( on_complete != null )
				{
					return on_complete(error);
				}
			}
		);
	}
	
	
	// If the new playtoken requires verification before it can be used
	this.show_panel_new_name = function(login_request_data)
	{
		var show_this_page = false;
		panel_clear_all();
		
		panel_set_title( "Nickname" );

		var html_all = "";
		html_all += "<div>"+CoinModeTranslate.translate("Your Name")+"</div><input id='coinmode_displayname' name='coinmode_displayname' class='coinmode_inputbox'  tabindex='0'></input>";
		$('#coinmode_subbox').html( html_all );

		$('#coinmode_displayname').focus();
		$('#coinmode_displayname').select();
		
		buttons_add( "Back", function()
			{
				that.show_panel_get_userid();
			}
		);		
		buttons_add( "Next", function()
			{
				spinner_show();
				buttons_disable();
				var display_name = $('#coinmode_displayname').val();
				that.api_call( "/players/create_new", 
					{
						game_id		: that.params.game_id,
						player_id	: -1, // TODO: Allow player referals
						referal_key	: that.params.game_id,
						display_name : display_name
					},
					function(error, data)
					{
						spinner_hide();
						
						if( error )
						{
							try
							{
								error = error.error;
							}
							catch(e)
							{
							}
							panel_error_show(error);
							buttons_enable();
						}
						else
						{
							that.m_uuid = data.uuid;
							that.set_last_client_id( that.m_uuid );
							that.m_is_new_user = true;
							that.set_last_display_name( display_name );
							console.log( "New UUID:"+that.m_uuid );
							
							that._request_new_playtoken( that.m_uuid );
							// SR: Perhaps do this to show the round info?  show_round_info
						}
					}
				);		
				
			}
		);
	}

	
	// If the new playtoken requires verification before it can be used
	this._show_panel_playtoken_verify = function(login_request_data, on_complete)
	{
		var show_this_page = false;
		panel_clear_all();
		
		panel_set_title( "Login Verify" );
		
		// Only show a password box if the user has a password set
		var html_all = "";
		if( login_request_data['password_version'] != null )
		{		
			html_all += "<div>"+CoinModeTranslate.translate("Password")+"</div><input id='coinmode_password' type='password' name='coinmode_password' class='coinmode_inputbox'></input>";
			show_this_page = true;			
		}

		// Only show the 2FA option if this is enabled
		if( login_request_data['twofactor_enabled'] )
		{		
			html_all += "<div>"+CoinModeTranslate.translate("Two Factor Authentication")+"</div><input id='coinmode_two_factor' name='coinmode_two_factor' class='coinmode_inputbox' tabindex='1'></input>";
			show_this_page = true;
		}
		
		if( show_this_page )
		{		
			$('#coinmode_subbox').html( html_all );
			buttons_add( "Back", function()
				{
					on_complete("back");
					//that.show_panel_get_userid();
				}
			);		
			buttons_add( "Next", function()
				{
					spinner_show();
					buttons_disable();
					//buttons_disable();
					var name = $('#coinmode_round_name').val();
					var coinmode_password = $('#coinmode_password').val();
					var coinmode_two_factor = $('#coinmode_two_factor').val();
					
					var coinmode_password_hash = coinmode_password;
					var verify_nonce = 0;

					// First get the has based on the user password
					
					if( login_request_data['password_version'] == 1 )
					{
						var string_to_hash = login_request_data['uuid'] + coinmode_password;
						var shaObj2 = new jsSHA("SHA-256", "TEXT" );
						shaObj2.update(string_to_hash);
						coinmode_password_hash = shaObj2.getHash("B64");

						var login_nonce = login_request_data['login_nonce'].toString();
						var hash = "";
						while( hash.substring(0,2) != "00" )
						{							
							var string_to_hash = (verify_nonce.toString()) + string_to_hash + login_nonce;
							var shaObj = new jsSHA("SHA-256", "TEXT" );
							shaObj.update(string_to_hash_with_nonce);
							var hash = shaObj.getHash("HEX");
							verify_nonce++;
						}
						alert( "pow_nonce:"+verify_nonce+ "Hash:"+hash );
				

					}
					
					// Do some proof of work and find a nonce that validates this request and uses CPU cycles to prevent brute forcing.
					that.api_call( "/players/playtokens/verify",
						{
							uuid 				: that.m_uuid,
							verify_nonce		: name,
							password_hash		: coinmode_password_hash,
							twofactor			: coinmode_two_factor,
							verify_nonce		: verify_nonce,
						},
						function( error, data )
						{
							spinner_hide();
							console.log("error:");
							console.log(error);
							console.log("data");
							console.log(data);
							
							if( error )
							{
								var display_error = "Error";
								try
								{
									if( error['error'].indexOf("Password incorrect")>=0)
									{
										display_error = CoinModeTranslate.translate( "Incorrect Password" );
									}
								}
								catch(e)
								{
									console.log("error in password:"+e);
								}
								panel_error_show( display_error );
								buttons_enable();
							}
							else
							{
								//that.show_panel_rounds_if_necessary();
								on_complete(null);
							}
						}
					);
				}
			);	
		}		
		else
		{
			// No password or 2FA so skip this and show next page.
			on_complete(null);
			//that.show_panel_rounds_if_necessary();
		}
	}
	
	

	// If the game has been started without a round_id this will bring up the selector so the user can choose which round to join and optionally create a new round if necessary
	this.show_panel_rounds_if_necessary = function()
	{
		panel_clear_all();
		
		if( that.m_attempt_to_join_round_id != null )
		{
			panel_set_title( "Joining Round" );
			spinner_show();
			buttons_disable();
								
			that.show_top_up_and_get_session_token( that.m_attempt_to_join_round_id, that.m_attempt_to_join_passphrase, function(err)
				{
					if( err )
					{
						// Show round selection page again.
						that.m_attempt_to_join_round_id = null;
						that.m_attempt_to_join_passphrase = null;
						//panel_error_show( err );
						
						that.show_panel_rounds();
					}
					else
					{
						// The player has been invited to play this game so show the sharing options.
						that.show_panel_new_round_share_options();
					}
				}
			);
		}
		else
		{
			that.show_panel_rounds();			
		}
	}

	

	this.show_panel_rounds = function()
	{	
		var keep_error_messages = true;
		panel_clear_all( keep_error_messages );
		

		panel_set_title( "Select Round" );
		buttons_add( "Log Out", function()
			{
				that.show_panel_login_or_new_user();
				//that._show_panel_cancel_refresh();
				//that._start_game( "User cancelled" );
			}
		);		
		buttons_add( "Refresh", function()
			{
				that._show_panel_update_rounds();
			}
		);		

		// Show searching
		$('#coinmode_subbox').html( "<div id='coinmode_round_area_items' class='coinmode_round_area'><div style='text-align:center'>"+CoinModeTranslate.translate( "Searching" )+"</div></div>" );

		// Get the rounds available
		spinner_show();
		
		that._show_panel_cancel_refresh();
		this.m_panel_update_rounds_counter = 0;
		this.m_panel_update_timer = setInterval( function()
			{
				that.m_panel_update_rounds_counter--;
				if( that.m_panel_update_rounds_counter < 0 )
				{
					// Reset the countdown inside the show_panel.
					that._show_panel_update_rounds();
				}
				
				var refresh_text = "Refreshing...";
				
				if( that.m_panel_update_rounds_counter > 0 )
				{
					var seconds = " seconds";
					if( that.m_panel_update_rounds_counter == 1 )
					{
						seconds = " second";
					}
					refresh_text = "Refreshing in " + that.m_panel_update_rounds_counter + seconds;
				}
				$('#coinmode_panel_update_rounds_counter').text( refresh_text );
			},
			1 * 1000 
		);
	}
	
	
	this._show_panel_cancel_refresh = function()
	{
		if( that.m_panel_update_timer != null )
		{
			clearInterval( that.m_panel_update_timer );
			that.m_panel_update_timer = null;
		}		
	}
	
	// Call this to update the panel
	this._show_panel_update_rounds = function()
	{		
		that.m_panel_update_rounds_counter = 30;
		var show_locked_rounds = false;
		
		if( that.params['show_locked_rounds'] )
		{
			show_locked_rounds = true;
		}
	
		that.api_call( "/games/find_rounds",
			{
				game_id		: that.params.game_id,
				show_locked_rounds : show_locked_rounds
			},
			function( error, data )
			{
				spinner_hide();
				
				if( error )
				{
					panel_error_show( error );
					buttons_enable();
				}
				else
				{
				}
								
				// Now display some round info.
				if( data['rounds'] != null )
				{
					// We have some rounds to show
					var rounds = data['rounds'];
					var round_html = "";
					var row_tag = "coinmode_round_row_";
					if( rounds.length > 0 )
					{
						// Add new round option
						// if( params['allow_create_round'] )
						{
						round_html += "\
							<div id='"+row_tag+"_new"+"' class='coinmode_round_row_new'>\
								<span class='coinmode_round_row_remaining'>New Round<span></span></span>\
								<span class='coinmode_round_row_age'>Create a new round here</span>\
								<span class='coinmode_round_row_players'></span>\
							</div>";						
						}
						
						for( var i=0; i < rounds.length; i++ )
						{
							var round = rounds[i];
							var locked = '';
							if( round['requires_passphrase'] )
							{
								// img/padlock_12.png
								locked = '<img src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAkAAAAMCAYAAACwXJejAAAABGdBTUEAALGPC/xhBQAAAAlwSFlzAAAOwgAADsIBFShKgAAAABl0RVh0U29mdHdhcmUAcGFpbnQubmV0IDQuMC4xMK0KCsAAAAB6SURBVChThYyxDYAwDARjMweDMQI7MBBIVKmYgYICOiahC/+RQciyhKXLx+fEyUpABzLYLNnT12rABIqInKqamezBCBSkngLD4RFM6/mQ87Ti5458V1tBy4Fc2Vxg5iUoes7rygW0AfSc1+OPUHpC6QmlJ5SeUH5I5QYOxkzXGiGAZQAAAABJRU5ErkJggg=="></img>';
							}
							var restrictions = '';
							var round_name = round['name'];
							if( round['sessions_remaining'] != null )
							{
								if( round['sessions_remaining'] >= 0 )
								{
									restrictions =  '('+round['sessions_remaining'] + ' Remaining)';
								}
							}							
							
							
							
							var players = "";//alice, bob, cat, dog, eragon, felix, ghost, ... ";
							var player_class = "coinmode_round_row_players_found";
							var array_players = round['players'];
							// For each player in this round, add their name to the list
							for( var p = 0; p < array_players.length; p++)
							{
								var playerinfo = array_players[p];
								// Add a comma after any previous names
								if( players != "" )
								{
									players += ",";
								}
								players += playerinfo['display_name'];
							}
							if( players == "" )
							{
								player_class = "coinmode_round_row_players_notfound";
								players = CoinModeTranslate.translate( "No players yet" );
							}
							var date_created = '';
								
							// Return the date as text
							date_created = epoch_to_text( round['epoch_round_started'] );
							
							
							round_html += "\
								<div id='"+row_tag+i+"' class='coinmode_round_row'>\
									<span class='coinmode_round_row_remaining'>"+locked+round_name+"<span class='coinmode_smallsubtletext'>"+restrictions+"</span></span>\
									<span class='coinmode_round_row_age'>"+date_created+"</span>\
									<span class='coinmode_round_row_players "+player_class+"'>"+players+"</span>\
								</div>";
						}
						
					}
					else
					{
						
						if( that.params['auto_create_new_round_if_none_found'] == true )
						{
							console.log("No rounds found and option to auto create new rounds set so jumping to round creation...");
							that._show_panel_cancel_refresh();
							that.show_panel_create_round_passphrase();
							return;
						}
						
					round_html += "\
						<div id='"+row_tag+"_new"+"' class='coinmode_round_row_new'>\
							<span class='coinmode_round_row_remaining'>No Active Rounds Found<span></span></span>\
							<span class='coinmode_round_row_age'>Create New Round</span>\
							<span class='coinmode_round_row_players'></span>\
						</div>";
					}

					
					var round_header = "<div id='coinmode_panel_update_rounds_counter' class='coinmode_refresh_text'></div>";


					$('#coinmode_subbox').html( round_header + "<div id='coinmode_round_area_items' class='coinmode_round_area'> "+round_html+"</div>" );
					// Set up click events
					
					// New round option
					$('#'+row_tag+"_new").click( function(e) 
						{
							that._show_panel_cancel_refresh();
							that.show_panel_create_round_passphrase();
						}
					);

					// Selecting an existing round
					for( var i = 0; i < rounds.length; i++ )
					{
						var round = rounds[i];
						$('#'+row_tag+i).click( function(e) 
							{
								
								// Stop any refreshing after this has been done.
								if( that.m_panel_update_timer != null )
								{
									clearInterval( that.m_panel_update_timer );
									that.m_panel_update_timer = null;
								}
								console.dir( e );
								var row_name = e.target.id;
								if( ( row_name == "" ) || ( row_name == null )) 
								{
									row_name = e.target.parentNode.id;
								}
								var row_id = parseInt( row_name.substring( row_tag.length ), 10 );
								
								var round = rounds[row_id];
								console.log( round );
								var requires_passphrase = true;
								that.m_attempt_to_join_round_id = round.round_id;
								that.m_attempt_to_join_passphrase = "";
								if( round['requires_passphrase'] )
								{									
									that.m_attempt_to_join_passphrase = prompt( CoinModeTranslate.translate("Passphrase to join this round") );
									that.m_attempt_to_join_passphrase = sanitise_passphrase( that.m_attempt_to_join_passphrase );

									if( that.m_attempt_to_join_passphrase == "" )
									{
										// cancelled
										spinner_show();
										buttons_disable();
										return;								
									}
								}
								
								spinner_show();
								buttons_disable();
								
								that.show_top_up_and_get_session_token( that.m_attempt_to_join_round_id, that.m_attempt_to_join_passphrase, function(err)
									{
										if( err )
										{
											// Do nothing
											//panel_error_show( err );
											that.show_panel_rounds();
										}
										else
										{
											that.show_panel_new_round_share_options();
										}
									}
								);
							}
						);						
					}
				}
			}
		);
	}
	
	
	
	// This will try to get a session token, if it can't it will pop up the top up page if allowed, otherwise it returns an error.
	// on_complete(null, session_token) is called once a valid session token has been found.
	this.show_top_up_and_get_session_token = function( round_id, passphrase, on_complete )
	{
		this._request_session( round_id, passphrase, function(err, details)
			{
				if( err )
				{
					switch( err )
					{
						case "not_waiting_to_play":
							panel_error_show("This round has completed and can no longer be joined.  Please find a new round to join or create a new one" );
							that.show_panel_rounds();
							break;
						case "passphrase invalid":
							// The round doesn't exist so explain why
							panel_error_show("The passphrase "+passphrase+" was invalid so unable to join");
							that.show_panel_rounds();
							break;
						case "not_exist":
							// The round doesn't exist so explain why
							panel_error_show("This round no longer exists.  Please find a new round to join or create a new one" );
							that.show_panel_rounds();
							break;
						case "insufficient_funds":
						{
							// Show top up here
							var amount_required_in_satoshi_fee = parseFloat(that.m_fee_play_session);
							var amount_required_in_satoshi_pot = parseFloat(that.m_pot_contribution);
							var amount_required_in_satoshi_total = amount_required_in_satoshi_fee + amount_required_in_satoshi_pot;
							
							that.show_topup_page( amount_required_in_satoshi_total, 
								function()
								{
									return( 
										that.currency_format_with_btc_and_local(amount_required_in_satoshi_total) + 
										"<br/><div class='coinmode_smallsubtletext'>(Developer wages:" + 
										that.currency_format_with_btc_and_local(amount_required_in_satoshi_fee) + 
										"<br/>Round Pot Contribution fee:" + 
										that.currency_format_with_btc_and_local(amount_required_in_satoshi_pot)+")</div>");
								},
								function(err)
								{
									// err is set if cancelled or an error
									// no-err response means the threshold topup was reached
									
									if( err )
									{
										if( err != "cancel" )
										{
											panel_error_show("Your account does not have enough funds to join this round." );
										}
										that.show_panel_rounds();
										var details_topup = {};
										
										return on_complete( err, details_topup );
									}
									// Top up completed
									// Try the session again.
									// Recursively call itself, not particularly happy about this approach but will have to do without a state machine.
									that.show_top_up_and_get_session_token( round_id, passphrase, on_complete );
								}
							);	
							break;
						}
						default:
							alert("Unhandled error in request session response:"+err );
							break;
					}
				}
				else
				{					
					// Set the passphrase that worked
					that.m_round_name = details['round_name'];
					that.m_passphrase = passphrase;
					
					// It succeed fine so call the on_complete to invoke the next screen
					on_complete(null);
				}
			}
		);
	}
	
	
	
	
	this._request_session = function( round_id, passphrase, on_complete )
	{		
		spinner_show();
		that.api_call( "/games/round/request_session", 
			{
				login_token:that.m_login_token,
				play_token:that.m_play_token,
				round_id:round_id,
				passphrase:passphrase,
			},
			function( error, data )
			{
				console.log("request_session data...");
				console.log(data);
				
				spinner_hide();

				//if( true )
										
				if( error )
				{	
console.log("Error while requesting session:" );			
console.log( error );		
					var errmsg = error;
					if( error['error'] != null )
					{
						errmsg = error['error'];
					}
					if( errmsg == "unable to find round" )
					{
						return on_complete( "not_exist" );
					}	
										
					if( errmsg == "round is not in state waiting to play." )
					{
						return on_complete( "not_waiting_to_play" );
					}	

					if( errmsg == "passphrase invalid" )
					{
						return on_complete( "passphrase invalid" );
					}	
					
					
					
					// TODO Remove RB3 flags					
					var details = error['details'];
					if( details != null )
					{
						that.m_fee_play_session = details['fee_play_session'];
						that.m_pot_contribution = details['pot_contribution'];
					}
					else
					{
						alert("Invalid response from request_session, no details found");
						that.m_fee_play_session = 0;
						that.m_pot_contribution = 0;
					}
	
					
					if( ( error['error'] == "insufficient funds" ) || ( error['error'] == "RB3:insufficient funds" ) )
					{
						return on_complete( "insufficient_funds" );
					}
					else
					{
						panel_error_show(error['error']);
						return on_complete( "error" );
					}
					buttons_enable();
				}
				else
				{
					// Save the fee play per session and pot contribution.
					that.m_fee_play_session = data['fee_play_session'];
					that.m_pot_contribution = data['pot_contribution'];
					
					that.m_round_id = round_id;

					that.m_session_token = data.session_token;
					on_complete( null, that.m_session_token );
				}
			}
		);		
	}

	
	/*
	this._request_sessionOLD = function( round_id, passphrase, on_complete )
	{
		
		that.api_call( "/games/round/request_session", 
			{
				login_token:that.m_login_token,
				play_token:that.m_play_token,
				round_id:round_id,
				passphrase:passphrase,
			},
			function( error, data )
			{
				console.log("request_session data...");
				console.log(data);
				
				spinner_hide();

				//if( true )
										
				if( error )
				{	
console.log("Error while requesting session:" );			
console.log( error );		
					var errmsg = error;
					if( error['error'] != null )
					{
						errmsg = error['error'];
					}
					if( errmsg == "unable to find round" )
					{
						return on_complete( "This round no longer exists.  Please find a new round to join or create a new one" );
					}	
										
					if( errmsg == "round is not in state waiting to play." )
					{
						return on_complete( "This round has completed and can no longer be joined.  Please find a new round to join or create a new one" );
					}	

					if( errmsg == "passphrase invalid" )
					{
						return on_complete( "The passphrase "+passphrase+" was invalid so unable to join" );
					}	
					
					
					
					// TODO Remove RB3 flags
					
					var details = error['details'];
					if( details != null )
					{
						that.m_fee_play_session = details['fee_play_session'];
						that.m_pot_contribution = details['pot_contribution'];
						//that.m_session_token = details['session_token']; // Whilst available here, not setting it yet because it's not valid until enough funds exist as start will fail.
					}
					else
					{
						alert("Invalid response from request_session, no details found");
						that.m_fee_play_session = 0;
						that.m_pot_contribution = 0;
					}
	
					
					if( ( ( error['error'] == "insufficient funds" ) || ( error['error'] == "RB3:insufficient funds" ) )&&
						( that.params['allow_topup_page'] != false ) )
					{
						// TODO: Handle the error correctly, only do this if insufficient funds exist
						// If there is insufficient funds, show the topup code.
						that.show_topup_page( function(error2)
							{
								if( error2 )
								{
									alert("Error on topup:"+error2);
								}
								that.m_round_id = round_id;

								that.m_session_token = details.session_token;
								return on_complete( error2 );
							}
						);
					}
					else
					{
						panel_error_show(error['error']);
						return on_complete( "error" );
					}
					buttons_enable();
				}
				else
				{
					// Save the fee play per session and pot contribution.
					that.m_fee_play_session = data['fee_play_session'];
					that.m_pot_contribution = data['pot_contribution'];
					
					that.m_round_id = round_id;

					that.m_session_token = data.session_token;
					on_complete( error );
				}
			}
		);		
	}
	*/
	
	this.m_currency_rates = {};
	this.m_default_currency_type = this.get_display_currency();
	get_currency_rates();
	
	
	// currency_string is "btc", "credits", "satoshis", "gbp", etc...
	function change_default_currency_type( currency_string )
	{
		var array_types = Object.keys( that.m_currency_rates );
		var new_index = array_types.indexOf(currency_string);
		
		if( ( currency_string == "" ) || ( currency_string == null ) )
		{
			currency_string = "usd";
		}
		// Did we find a match?
		if( ( new_index >= 0 ) && ( currency_string != "" ) )
		{
			that.set_display_currency( currency_string );
			that.m_default_currency_type = array_types[new_index];
			return;
		}
		
		var current_index = array_types.indexOf(that.m_default_currency_type);
		current_index++;
		if( current_index > array_types.length )
		{
			current_index = 0;			
		}
		that.m_default_currency_type = array_types[current_index];
		if( that.m_default_currency_type == null )
		{
			console.log("Currency type not found, using null");
		}
	
	}
	
	
	function get_currency_rates()
	{		
		that.api_call( "/info/convert_value", 
			{ 
				value: "1", 
				currency_in:"btc", 
				currency_out: null // All supported currencies
			}, 
			function( error, data )
			{
				if( error == null )
				{
					that.m_currency_rates = {};
					
					that.m_currency_rates = data;
					
					/*
					// Only use the currencies where we have a valid conversion rate. (I.e. status and duration fields will be removed from this)
					var keys = Object.keys( data );
					for( var i = 0; i < keys.length; i++ )
					{
						var key = keys[i];
						var item = data[key];
						if( item['satoshi_rate'] > 0 )
						{
							that.m_currency_rates[ key ] = item;
						}
					}
					*/
					console.log("currency rates updated");
				}
				else
				{
					console.log("error getting latest currency rates");
				}
			}
		);
	}
	
	
	this.currency_format_with_btc_and_local = function( satoshis )
	{
		var local_currency_type = this.get_display_currency();
		return this.currency_format( satoshis, "BTC", true ) + " <span class='coinmode_currency_local_all'>"+this.currency_format( satoshis, local_currency_type, true )+"</span>";
	}
	
	this.currency_format = function( satoshis, currency_to_display_as, allow_html_markup )
	{
		var formatted_text = "";
		if( currency_to_display_as == null )
		{
			currency_to_display_as = that.m_default_currency_type;
		}
		
		var data = that.m_currency_rates[currency_to_display_as];
		if( data != null )
		{
			// Found rates to use
			var accuracy = data['rounded'];
			if( accuracy == null )
			{
				accuracy = 2;
			}
			formatted_text = (satoshis / data['satoshi_rate']).toFixed( accuracy );
			if( ( formatted_text == "0.00" ) && 
				( satoshis > 0 ) )
			{
				formatted_text = (satoshis / data['satoshi_rate']).toFixed(8);
				// Remove trailing 0's
				formatted_text = formatted_text.replace( /0+$/, "" );
				if( formatted_text == "0." )
				{
					formatted_text = "0";
				}
			}
			formatted_text = data['prefix'] + formatted_text;
			if( allow_html_markup )
			{
				formatted_text += ' <span class="coinmode_currency_local_postfix">'+ data['postfix'] + '</span>';
			}
			else
			{
				formatted_text += data['postfix'];
			}
		}
		else
		{
			// Use BTC because we don't know have conversion rates for this yet.
			formatted_text = (satoshis / 100000000).toFixed(8);
			// Remove trailing 0's
			formatted_text = formatted_text.replace( /0+$/, "" );
			if( formatted_text == "0." )
			{
				formatted_text = "0";
			}
			if( allow_html_markup )
			{
				formatted_text += '<span class="coinmode_currency_local_postfix">BTC</span>';			
			}
			else
			{
				formatted_text += 'BTC';
			}
		}
		return formatted_text;
	}
	
	
	// Using global variables... TODO remove this.
	var paymenturi = "";
	var bitcoin_address = "";
	
	// Used by show_topup_page to refresh the QR code with the latest amounts required
	function __update_qr_deposit( bitcoin_address, amount_required_in_satoshi_total, balance_current, balance_pending, display_payment_details )
	{
		var min_amount = (0.4 / 1000) * 100000000;
		
		var html_details = display_payment_details( balance_current, balance_pending );
		$('#coinmode_requiredamount').html( html_details );


		// Update the QR code with the correct amount in
		var amount_required_in_bitcoin_total = ( amount_required_in_satoshi_total - balance_current - balance_pending ) / 100000000;
		paymenturi = "bitcoin:"+bitcoin_address + "?amount="+amount_required_in_bitcoin_total+"&message=CoinMode%20Deposit%20To%20"+(that.get_last_display_name().substring(0,15));
		if( amount_required_in_bitcoin_total < min_amount )
		{
			//paymenturi = "bitcoin:"+bitcoin_address + "?message=CoinMode%20Deposit&label=CoinMode";
			paymenturi = "bitcoin:"+bitcoin_address + "?message=CoinMode%20Deposit%20To%20"+(that.get_last_display_name().substring(0,15));
		}
		
		$('#coinmode_qrcode').html("");
		$('#coinmode_qrcode').qrcode(paymenturi);
	}
	
	
	
	// amount_required_in_satoshi_total - Amount to wait for to be available in the users account before proceeding
	// display_payment_details - Function to call to return the HTML to display the payment information for the user.  E.g. Why we are asking for them to deposit funds.
	// on_complete(err) - err is "cancelled" if cancelled button was pressed.  if err is null, the amount_required_in_satoshi_total was reached
	this.show_topup_page = function( amount_required_in_satoshi_total, display_payment_details, on_complete)
	{
		var refreshtimer = null;
		// Show a pop up modal to allow the user to deposit funds.
		panel_clear_all();
		
		var start_fee = "$0.00";
		bitcoin_address = "";
		
		panel_set_title( "Not enough credit available..." );
		
		// If testnet go to a faucet rather than purchase
		var testnet = that.params['testnet'];
		if( testnet )
		{
			buttons_add( "Get Coins", function()
				{
					window.open("https://kuttler.eu/en/bitcoin/btc/faucet/", "_blank");
				}
			);
		}
		else
		{
			buttons_add( "Purchase", function()
				{
					window.open("https://quickbitcoin.co.uk/", "_blank");
				}
			);
		}
		buttons_add( "Cancel", function()
			{
				if( refreshtimer == null )
				{
					clearInterval(refreshtimer);
					refreshtimer = null;
				}
				on_complete("cancelled"); // Send an error back if this is being cancelled								
			}
		);		

		
		spinner_show();
		setTimeout( function()
			{
				buttons_disable();
			}
			,0 );
		that.api_call( "/players/wallet/get_deposit_address",
			{
				login_token : that.m_login_token,
				play_token : that.m_play_token,
				currency_type : that.m_currency_type,
				new_address : false
			},
			function( error, data )
			{
				spinner_hide();
				buttons_enable();
				
				if( error )
				{
					panel_error_show( error );
					buttons_enable();
				}
				else
				{
					console.log("SR: Get Deposit Address response data...");
					console.log(data);
					bitcoin_address = data['address'];
				}
		
		
				
				$('#coinmode_subbox').html( "<div class='coinmode_warningtext'>Insufficient Funds</div><div>Your account balance</div> <div id='coinmode_balance' class='coinmode_large_centered'></div>" );
				$('#coinmode_subbox').append( "<div>Minimum deposit to Coinmode required</div> <div id='coinmode_requiredamount' class='coinmode_large_centered'></div>" );
				$('#coinmode_subbox').append( "<div class='coinmode_send_funds'>Send funds to your Coinmode address" );
				$('#coinmode_subbox').append( "<div id='coinmode_bitcoinaddress' class='coinmode_bitcoinaddress'>"+bitcoin_address+"</div>" );
				$('#coinmode_subbox').append( "<div class='coinmode_refresh_text'>Refreshing in <span id='coinmode_refreshtime'></span></div>" );
				$('#coinmode_subbox').append( "<div id='coinmode_qrcode'></div>" );
				
				//$('#coinmode_qrcode').qrcode(paymenturi);
				
				

				/*
				$('#coinmode_cancel').click( function()
					{
						clearInterval(refreshtimer);
						refreshtimer = null;
						// Ok, proceed
						on_complete("cancelled"); // Send an error back if this is being cancelled																
					}
				);
				*/

				$('#coinmode_bitcoinaddress').click( function()
					{
						on_copy_link('coinmode_bitcoinaddress');
						panel_error_show("Address copied");
					}
				);

				$('#coinmode_qrcode').click( function()
					{
						on_copy_link('coinmode_bitcoinaddress');
						open_location( paymenturi );
					}
				);

				// Put in a function so the click can easily change the currency type.

				$('#coinmode_requiredamount').click( function()
					{
						change_default_currency_type();
						var confirmed = 0;
						var pending = 0;
						try
						{
							confirmed = balance['confirmed'];
							pending = balance['pending'];
						}
						catch(e)
						{
							console.log("Error getting balance value");
						}
						__update_qr_deposit( bitcoin_address, amount_required_in_satoshi_total, balance['confirmed'], balance['pending'], display_payment_details );
					}
				);				
				
				$('#coinmode_balance').click( function()
					{
						change_default_currency_type();
						__update_qr_deposit( bitcoin_address, amount_required_in_satoshi_total, balance['confirmed'], balance['pending'], display_payment_details );
					}
				);
				
				// Show some sort of QR code
				__update_qr_deposit( bitcoin_address, amount_required_in_satoshi_total, 0, 0, display_payment_details );
				
				// Keep checking for balance change.
				var counter = 0;
				
				that.m_refresh_balance_interval = 5;
				
				refreshtimer = setInterval( function()
				{
					//miyJd1xtMxUCKiKdAQ2dK74YQUoF7hbqDT					
							
					counter = counter - 1;
					$('#coinmode_refreshtime').text(counter);

					if( counter <= 0 )
					{
						counter = that.m_refresh_balance_interval;
						that.api_call( "/players/wallet/get_balance",
							{
								login_token : that.m_login_token,
								play_token : that.m_play_token,
								currency_type : that.m_currency_type
							},
							function( error, data )
							{
								spinner_hide();
								buttons_enable();
								var newhtml = "";
								if( error )
								{
									console.log("Error obtaining balance:"+ error);
									newhtml = "Unable to obtain balance yet";
								}
								else
								{
									var balance = data['balance'];
									if( balance['confirmed'] != null )
									{
										newhtml = that.currency_format_with_btc_and_local(balance['confirmed']);
										if( balance['pending'] > 0 )
										{
											newhtml += "<br/>(Incoming "+that.currency_format(balance['pending'])+")";
										}
										
										// Have we got enough money to try again?
										if( balance['confirmed'] > amount_required_in_satoshi_total )
										{
											clearInterval(refreshtimer);
											refreshtimer = null;
											// Ok, proceed
											on_complete(null); // Send an error back if this is being cancelled										
										}
										else
										{
											// There is still not enough funds to proceed, will check on next interval
											// TODO: Listen on a webhook when payment has been made
										}
										
										__update_qr_deposit( bitcoin_address, amount_required_in_satoshi_total, balance['confirmed'], balance['pending'], display_payment_details );

									}
									else
									{
										console.log("Data...");
										console.log(data);
										newhtml = "No balance found yet...";
									}
								}
								
								$('#coinmode_balance').html( newhtml );
													
							}
						);						
					}
				}, 1*1000 
				); // timer
			} // api get_balance callback 
		);	
	}
	
	
	
	// If the user is allowed to create a new round and selected the 'New Round' button
	this.show_panel_create_round_passphrase = function()
	{
		panel_clear_all();
		
		var start_fee = "$0.00";
		panel_set_title( "Create New Round" );
		
		// Get the price to create a new round
		var fee_create_new_round = 0;
		var fee_play_session = 0;
		
		
		spinner_show();
		
		that.api_call( "/games/get_info", { game_id: that.params['game_id'] }, function( error, data_game_info )
			{
				spinner_hide();
				if( error )
				{
					panel_error_show( error );
					buttons_enable();
					
				}
				
				var game_details = data_game_info['game_details'];
				
				if( game_details['fee_create_new_round'] > 0 )
				{
					fee_create_new_round = parseInt( game_details['fee_create_new_round'], 10 );
				}				
				if( game_details['fee_play_session'] > 0 )
				{
					fee_play_session = parseInt( game_details['fee_play_session'], 10 );
				}
				
				var tab_index_ok = 2;

				var html_round = "";
				html_round += "<div>Create New Round</div><input id='coinmode_round_name' class='coinmode_inputbox' tabindex='0' placeholder='Round Name'></input>";
				
				if( that.params['newround_passphrase_allow_user_entered'] )
				{
					html_round += "<div>Passphrase</div><input id='coinmode_round_passphrase' class='coinmode_inputbox' tabindex='1'></input>";
					tab_index_ok = 3;
				}
				
				if( fee_create_new_round > 0 )
				{
					html_round += "<div class='coinmode_text_heading'>Fee to create a new round</div><div class='coinmode_center'><div id='coinmode_round_create_fee' class='coinmode_currency_blob'></div></div>";
				}				
				if( fee_play_session > 0 )
				{
					html_round += "<div>Fee other players play to join</div><div class='coinmode_center'><div id='coinmode_round_play_fee' class='coinmode_currency_blob'></div></div>";
				}
				
				html_round += "<div class='coinmode_text_heading'>Players put into pot (optional)</div><input id='coinmode_round_pot_fee' class='coinmode_inputbox' value='"+start_fee+"' tabindex='" + ( tab_index_ok - 1 )+"'></input>";
				html_round += "<div id='coinmode_round_pot' class='coinmode_center'></div>";

				$('#coinmode_subbox').html( html_round );

				$('#coinmode_round_name').focus();
				$('#coinmode_round_name').select();
				
				that.on_round_fee_changed = function()
					{
						$('#coinmode_round_pot').html( "" );
						
						var creation_fee_text = that.currency_format_with_btc_and_local( fee_create_new_round );
						var fee_play_session_text = that.currency_format_with_btc_and_local( fee_play_session );
						$('#coinmode_round_create_fee').html(creation_fee_text);
						$('#coinmode_round_play_fee').html(fee_play_session_text);
						
						
						//spinner_show();
						// Send the human entered text to the service to convert it to satoshis
						var value_in = $('#coinmode_round_pot_fee').val();
						that.api_call( "/info/convert_value", { value: value_in, currency_out: null}, function( error, data )
							{
								//spinner_hide();
								var round_value_text = "";
								if( ( data['btc'] == null ) ||
									( error ) )
								{
									round_value_text = "Error";
									that.m_coinmode_round_pot_fee = 0;
								}
								else
								{
									that.m_coinmode_round_pot_fee = data['satoshis']['amount'];
								}
								
								round_value_text = that.currency_format_with_btc_and_local( that.m_coinmode_round_pot_fee );
								var conversion_html = "<div class='coinmode_currency_blob'>"+round_value_text+"</div>";
								
								$('#coinmode_round_pot').html( conversion_html );
							}
						);							
					};
					

				// Get the rates to be updated as entered
				that.on_round_fee_changed();
				$('#coinmode_round_pot_fee').change( that.on_round_fee_changed );
				$('#coinmode_round_pot_fee').keyup( that.on_round_fee_changed );
				
				buttons_add( "Cancel", function()
					{
						// Return to the rounds page				
						that.params['auto_create_new_round_if_none_found'] = false;
						that.show_panel_rounds_if_necessary(); // This has an issue that when autocreate new round is set it won't allow you to cancel to wait for new rounds.
						//that.try_auto_login();
					}
				);		
				
				
				
				buttons_add( "Start", function()
					{
						buttons_disable();

						var name = $('#coinmode_round_name').val();
						var passphrase = "";
						if( that.params['newround_passphrase_allow_user_entered'] == true)
						{
							passphrase = $('#coinmode_round_passphrase').val();
							
							passphrase = sanitise_passphrase( passphrase );
							
							if( that.params['newround_allow_empty_passphrase'] != true )
							{
								if( passphrase == "" )
								{
									panel_error_show( "You must enter a passphrase" );
									buttons_enable();										
									return;
								}
							}
						}
						else
						{
							passphrase = random_string( 6, "023456789abcdefghjkmnpqrxtuvwxy" );
						}
						var round_fee_satoshis = that.m_coinmode_round_dev_fee;
						var pot_contribution = that.m_coinmode_round_pot_fee;
						
						if( ( isNaN( pot_contribution ) || 
							( pot_contribution < 0 ) ) )
						{
							pot_contribution = 0;
						}
						
						that._create_new_round( name, passphrase, fee_create_new_round, fee_play_session, pot_contribution, function()
							{
								// Cancel was pressed therefore go back.
								show_panel_create_round_passphrase();
							}
						);
					}, null, tab_index_ok
				);		
			
						
			} // Get game info for the create round fee
		);
	}
	
	
	// Internal to do the API call to create a new round and show the top up page if allowed
	this._create_new_round = function( name, passphrase, fee_create_new_round, fee_play_session, pot_contribution, on_error )
	{
		spinner_show();
		
		that.api_call( "/games/round/create",
			{
				login_token			: that.m_login_token,
				play_token			: that.m_play_token,
				name				: name,
				passphrase			: passphrase,
				game_id				: that.params.game_id,
				pot_contribution	: pot_contribution,
			},
			function( error, data )
			{
				spinner_hide();

				if( error )
				{
					var errmsg = error;
					if( error['error'] != null )
					{										
						errmsg = error['error'];
						if( error['error'] == "missing login_token in request" )
						{
							errmsg = "Not logged in or no valid play token";
						}
						if( error['error'] == "RB3:insufficient funds" )
						{
							errmsg = "Your account needs more funds to create a new round for others to join.";
						}
					}


					if( that.params['allow_topup_page'] != false )
					{
						var amount_required_in_satoshi_total = fee_create_new_round + fee_play_session + pot_contribution;

						that.show_topup_page( amount_required_in_satoshi_total, 
							function()
							{
								return( 
									that.currency_format_with_btc_and_local(amount_required_in_satoshi_total) + 
									"<br/><div class='coinmode_smallsubtletext'>(Create New Round Fee:" + 
									that.currency_format_with_btc_and_local(fee_create_new_round) + " )</div>" + 
									"<div class='coinmode_smallsubtletext'>(Developer wages:" + 
									that.currency_format_with_btc_and_local(fee_play_session) + 
									"<br/>Round Pot Contribution fee:" + 
									that.currency_format_with_btc_and_local(pot_contribution)+")</div>");
							},
							function(err)
							{
								// err is set if cancelled or an error
								// no-err response means the threshold topup was reached
								
								if( err )
								{
									if( err != "cancel" )
									{
										panel_error_show("Your account does not have enough funds to create a new round." );
									}
									var details_topup = {};
									
									return on_error( err, details_topup );
								}
								
								// Recursive call to try and create the round again.
								that._create_new_round( name, passphrase, fee_create_new_round, fee_play_session, pot_contribution, on_error )

								/*
								// Save the name and passphrase, it may be needed later?
								that.m_round_name = name;
								that.m_passphrase = passphrase;
								
								
								// Top up completed
								// Try the session again.
								// Recursively call itself, not particularly happy about this approach but will have to do without a state machine.
								that.show_top_up_and_get_session_token( round_id, passphrase, on_complete );
								*/
							}
						);
					}
					else
					{
						on_error( errmsg );
					}
				}
				else
				{
					spinner_show();
					that.show_top_up_and_get_session_token( data['id_round'], passphrase, function(err)
						{
							if( err )
							{
								that.show_panel_rounds_if_necessary( data['id_round'], passphrase );
							}
							else
							{
								// All worked so start the game
								that.m_round_name = name;
								that.m_passphrase = passphrase;
								that.show_panel_new_round_share_options();
							}
						}
					);

				}
			}
		);
	}
	
	
	
	// If the user is allowed to create a new round and selected the 'New Round' button
	this.show_panel_new_round_share_options = function()
	{		
		if( that.params['show_share_link_page'] != false )
		{
			var link_to_share_raw = "http://www.coinmode.com";
			link_to_share_raw += "?round_id="+that.m_round_id+"&passphrase="+that.m_passphrase;
			var link_to_share_raw = "http://www.coinmode.com?round_id="+that.m_round_id+"&passphrase="+that.m_passphrase;
			var link_to_share_coinmode = "http://www.coinmode.com/r/"+that.m_round_id+"/"+that.m_passphrase;
			var link_to_share_encoded = link_to_share_coinmode;//encodeURIComponent( link_to_share_raw );
			
			var share = that.params.shareoptions;
			if( share == null )
			{
				share = {};
			}

			panel_clear_all();
			panel_set_title( "Click To Share Link" );
			
			var html = "<div>Share Round Link</div>";
			html += "<button id='coinmode_share_link' class='js-copy-btn' onclick='on_copy_link(\"coinmode_share_link\")';>"+link_to_share_coinmode+"</button><div id='coinmode_copied_popup' style='display:none'>Copied</div>";

			
			var zoom = 1.0;
			if( is_mobile() )
			{
				
				// Make smaller because we have more icons!
				zoom = 0.8;
			}
			html += '<div>Share Invite Link</div><ul class="coinmode_share_buttons" style="zoom:'+zoom+'">';
			
			
			//var title = "CoinMode%20Pong%20Invite%20(Round%20"+that['m_round_name']+")"; // This is the title people see
			var game_name = that.params.game_name;
			var title = encodeURIComponent("CoinMode "+game_name+" Invite (Round "+that['m_round_name']+")"); // This is the title people see
			var summary = link_to_share_coinmode;
			var description = "You have been invited to play "+game_name;  // The detailed description 
			//description += '\nTo play you can click this link\n<a href="'+link_to_share_coinmode+'"></a>\nor type '+link_to_share_coinmode;
			description += '\nTo play you can click this link\n'+link_to_share_coinmode;
			description = encodeURIComponent( description );
			
			// Email -->
			if (share['email'] != false)
			{
				// img/flat_web_icon_set/black/Email.png
				html += '<li><a href="mailto:?subject='+title+'&body='+description+'" target="_blank" title="Send email"><img alt="Send email" src="data:image/png;base64,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"></a></li>';
			}		
			// Facebook -->
			if (share['facebook'] != false)
			{
				//img/flat_web_icon_set/black/Facebook.png
				html += '<li><a href="https://www.facebook.com/sharer/sharer.php?u='+link_to_share_encoded+'" title="Share on Facebook" target="_blank"><img alt="Share on Facebook" src="data:image/png;base64,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"></a></li>';
			}
			// Reddit -->
			if (share['reddit'] != false)
			{
				//img/flat_web_icon_set/black/Reddit.png
				html += '<li><a href="http://www.reddit.com/r/coinmode/submit?url='+link_to_share_encoded+'&title='+title+'" target="_blank" title="Submit to Reddit"><img alt="Submit to Reddit" src="data:image/png;base64,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"></a></li>';
			}
			// Twitter -->
			if (share['twitter'] != false)
			{
				//img/flat_web_icon_set/black/Twitter.png
				html += '<li><a href="https://twitter.com/intent/tweet?source='+link_to_share_encoded+'&text='+title+':%20'+link_to_share_encoded+'" target="_blank" title="Tweet"><img alt="Tweet" src="data:image/png;base64,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"></a></li>';
			}
			//Linkedin -->
			if (share['linkedin'] != false)
			{
				html += '<li><a href="http://www.linkedin.com/shareArticle?mini=true&url='+link_to_share_encoded+'&title='+title+'&summary='+summary+'&source='+link_to_share_encoded+'" target="_blank" title="Share on LinkedIn"><img alt="Share on LinkedIn" src="data:image/png;base64,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"></a></li>';
			}
			// Google -->
			if (share['google'] != false)
			{
				html += '<li><a href="https://plus.google.com/share?url='+link_to_share_encoded+'" target="_blank" title="Share on Google+"><img alt="Share on Google+" src="data:image/png;base64,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"></a></li>';
			}
			// pinterest -->
			if (share['pinterest'] != false)
			{
				//img/flat_web_icon_set/black/Pinterest.png
				html += '<li><a href="http://pinterest.com/pin/create/button/?url='+link_to_share_encoded+'&media=http://www.coinmode.com/img/coinmode_square64.png&description='+summary+'" target="_blank" title="Pin it"><img alt="Pin it" src="data:image/png;base64,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"></a></li>';
			}		
			
			if( is_mobile() )
			{
				// whatsapp -->
				if (share['whatsapp'] != false)
				{
					//img/flat_web_icon_set/black/whatsapp.png
					html += '<li><a href="whatsapp://send?text='+link_to_share_encoded+'"><img alt="WhatsApp" src="data:image/png;base64,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"></a></li>';
				}
				// sms -->
				if (share['sms'] != false)
				{
					//img/flat_web_icon_set/black/sms.png
					var ua = navigator.userAgent.toLowerCase();
					var separator = "?";
					//If on iOS change ? to a ;
					if( is_ios() )
					{
						// For iOS 6 and 7 the separator should be a ';'
						// separator = ";";  // No longer supported
						// For iOS 8+ it should be a ampersand
						separator = "&";
					}
					html += '<li><a href="sms:'+separator+'body='+link_to_share_encoded+'"><img alt="WhatsApp" src="data:image/png;base64,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"></a></li>';
				}
			}
			
			html += '</ul>';
			
			
			
			$('#coinmode_subbox').html( html );
			
			buttons_add( "Cancel", function()
				{
					// Return to the rounds page				
					that.show_panel_rounds_if_necessary();
				}
			);		
			buttons_add( "Next", function()
				{
					buttons_disable();
					
					that.show_panel_start();
				}
			);		
		}
		else
		{
			that.show_panel_start();
		}
	}
	
	
	
	this.show_panel_start = function()
	{
		if( this.params.skip_start_screen )
		{
			// Start the game now
			that._start_game( null );
		}
	
		panel_clear_all();
		
		panel_set_title( "Ready?" );
		buttons_add( "Cancel", function()
			{
				alert("Cancel pressed");
			}
		);		
		buttons_add( "Start", function()
			{
				that._start_game( null );
			}
		);		
	}
	
	
	

	this.show_panel_review = function(on_complete)
	{
		panel_clear_all();
		
		panel_set_title( "Your Review" );
				
		$('#coinmode_subbox').html( "" );
		$('#coinmode_subbox').append( '<div>Rating\
			<div class="rate">\
				<input type="radio" id="star5" name="rating" value="5" /><label for="star5" title="text">5 stars</label>\
				<input type="radio" id="star4" name="rating" value="4" /><label for="star4" title="text">4 stars</label>\
				<input type="radio" id="star3" name="rating" value="3" /><label for="star3" title="text">3 stars</label>\
				<input type="radio" id="star2" name="rating" value="2" /><label for="star2" title="text">2 stars</label>\
				<input type="radio" id="star1" name="rating" value="1" /><label for="star1" title="text">1 star</label>\
			</div></div>');
				
		$('#coinmode_subbox').append( "<br/><div>Comments</div><textarea id='coinmode_round_review' placeholder='Type any comments to share with other players here'></textarea>" );
		

		buttons_add( "Skip", function()
			{
				on_complete(null, null);
			}
		);				
		
		buttons_add( "Submit Review", function()
			{
				spinner_show();
				buttons_disable();
				var passphrase = $('#coinmode_round_passphrase').val();
				var review_rating = $("input[name=rating]:checked").val();
				var review_text = $('#coinmode_round_review').val();
				var fairness = 5;
				var value_for_money = 5;
				that.api_call( "/games/round/session/review",
					{
						session_token 			: that.m_session_token,
						review_text				: review_text,
						review_rating			: review_rating,
						review_fairness			: fairness,
						review_value_for_money	: value_for_money,
					},
					function( error, data )
					{
						spinner_hide();
						
						if( error )
						{
							panel_error_show( error['error'] );
							buttons_enable();
						}
						else
						{
							// Saved
							console.log("CM: Yes saved review successfully");
							on_complete();
						}
					}
				);
			}
		);		
	}
		
	

	this.show_panel_complete_registration = function(on_complete)
	{
		panel_clear_all();
		
		panel_set_title( "Complete Registration" );
				
		$('#coinmode_subbox').html( "" );
		$('#coinmode_subbox').append( '<div>As a new user you can now complete your registration to continue using this account on other games.</div>');
		

		buttons_add( "Skip", function()
			{
				on_complete(null, null);
			}
		);				
		
		buttons_add( "Visit Coinmode.com", function()
			{
				spinner_show();
				buttons_disable();
				
				// Take them to the coinmode website to fully register
				window.location.replace("http://www.coinmode.com/intro.html?uuid="+that.m_uuid);
			}
		);		
	}
		
	
	
	
	on_initalised( null );	
	
}


function open_location(address)
{
	window.location.href = address;
	//window.location.replace = address;  // No history click
}


// Make sure we only allow alphanumeric values.  Spaces and other characters are stripped because it causes too many problems on link sharing
function sanitise_passphrase( passphrase_in )
{
	var passphrase_out = null;
	if( typeof( passphrase_in ) == 'string' )
	{
		passphrase_in = passphrase_in.toLowerCase().trim();
		passphrase_out = passphrase_in.replace(/[^0-9a-z]/gi, '_');
	}
	return passphrase_out;					
}


// Copy to clipboard
function on_copy_link( item_id )
{
	$('#coinmode_copied_popup').show();
	setTimeout( function()
		{
			$('#coinmode_copied_popup').fadeOut();
		}, 
		2000 
	);
	copyToClipboardMsg(document.getElementById(item_id), item_id );
}

function copyToClipboardMsg(elem, msgElem) {
	  var succeed = copyToClipboard(elem);
    var msg;
    if (!succeed) {
        msg = "Copy not supported or blocked.  Press Ctrl+c to copy."
    } else {
        msg = "Text copied to the clipboard."
    }
	
	/*
    if (typeof msgElem === "string") {
        msgElem = document.getElementById(msgElem);
    }
    msgElem.innerHTML = msg;
    setTimeout(function() {
        msgElem.innerHTML = "";
    }, 2000);
	*/
}

function copyToClipboard(elem) {
	  // create hidden text element, if it doesn't already exist
    var targetId = "_hiddenCopyText_";
    var isInput = elem.tagName === "INPUT" || elem.tagName === "TEXTAREA";
    var origSelectionStart, origSelectionEnd;
    if (isInput) {
        // can just use the original source element for the selection and copy
        target = elem;
        origSelectionStart = elem.selectionStart;
        origSelectionEnd = elem.selectionEnd;
    } else {
        // must use a temporary form element for the selection and copy
        target = document.getElementById(targetId);
        if (!target) {
            var target = document.createElement("textarea");
            target.style.position = "absolute";
            target.style.left = "-9999px";
            target.style.top = "0";
            target.id = targetId;
            document.body.appendChild(target);
        }
        target.textContent = elem.textContent;
    }
	target.readOnly = true;
    // select the content
    var currentFocus = document.activeElement;
    target.focus();
    target.setSelectionRange(0, target.value.length);
    
    // copy the selection
    var succeed;
    try {
    	  succeed = document.execCommand("copy");
    } catch(e) {
        succeed = false;
    }
    // restore original focus
    if (currentFocus && typeof currentFocus.focus === "function") {
        currentFocus.focus();
    }
    
    if (isInput) {
        // restore prior selection
        elem.setSelectionRange(origSelectionStart, origSelectionEnd);
    } else {
        // clear temporary content
        target.textContent = "";
    }
    return succeed;
}

//document.cookie =  'propertyName=test; path=/'