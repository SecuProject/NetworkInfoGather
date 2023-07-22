
/* 
 * NetworkInfoGather
 * Copyright (C) 2023  SecuProject
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

typedef struct {
	char favionMD5[MD5_HASH_SIZE + 1];
	const char* cmsName;
}FavionStruct;

/*
https://github.com/v4lproik/WIAS/blob/master/favicon-db
https://wiki.owasp.org/index.php/OWASP_favicon_database
https://github.com/ARPSyndicate/favinizer/blob/main/favinizer.yaml
https://www.apt-browse.org/browse/ubuntu/trusty/universe/all/w3af-console/1.1svn5547-1/file/usr/share/w3af/plugins/discovery/favicon/favicon-md5
https://vulners.com/openvas/OPENVAS:136141256231020108
*/

FavionStruct favionStruct[] = {
	"01febf7c2bd75cd15dae3aa093d80552","atlassian crucible or fisheye",
	"02dd7453848213a7b5277556bcc46307","phpmyadmin (2.11.8.1) - pmd",
	"02f4db63a9cfb650c05ffd82956cbfd6","proxmox",
	"032ecc47c22a91e7f3f1d28a45d7f7bc","ant docs (1.7.1) / libjakarta-poi-java (3.0.2)",
	"0488faca4c19046b94d07c3ee83cf9d6","spring java framework",
	"04d89d5b7a290334f5ce37c7e8b6a349","atlassian jira bug tracker",
	"05656826682ab3147092991ef5de9ef3","rapidshare",
	"05bc6d56d8df6d668cf7e9e11319f4e6","jive forums",
	"06b60d90ccfb79c2574c7fdc3ac23f05","movabletype-opensource (4.2~rc4)",
	"07e9163f7ca8cfe6c1d773f895fbebad","apache",
	"093551287f13e0ee3805fee23c6f0e12","freevo (1.8.1)",
	"09a1e50dc3369e031b97f38abddd10c8","ubiquiti ubiquiti m series / airos",
	"09b565a51e14b721a323f0ba44b2982a","google web server",
	"09d310e97902eefd0065f01c09c830fb","moodle",
	"09df839f1958f0add6b872dff4e0aa21","infoseek japan web hosting",
	"09f5ea65a2d31da8976b9b9fd2bf853c","caudium (1.4.12)",
	"0a99a23f6b1f1bddb94d2a2212598628","maraschino",
	"0ad3a7e2c3a7b144c04e73050a63df0b","ihouse real estate web hosting",
	"0b2481ebc335a2d70fcf0cba0b3ce0fc","ntop (3.3)",
	"0c53ef3d151cbac70a8486dd1ebc8b25","chamilo e-learning system",
	"0d42576d625920bcd121261fc5a6230b","mathomatic (14.0.6)",
	"0e14c2f52b93613b5d1527802523b23f","gforge (4.6.99+svn6496)",
	"0e2503a23068aac350f16143d30a1273","sql-ledger (2.8.15)",
	"0e6a6ed665a9669b368d9a90b87976a9","horde gollem (file manager)",
	"0ec12e5820517d3b62e56b9a8f1ee5bc","tradingeye",
	"0f45c2c79ebe90d6491ddb111e810a56","python-cherrypy (2.3.0-3.0.2)",
	"0f584138aacfb79aaba7e2539fc4e642","plex media server",
	"107579220745d3b21461c23024d6c4a3","d-link",
	"10bd6ad7b318df92d9e9bd03104d9b80","plone cms",
	"11abb4301d06dccc36d1b5f6dcad093e","ntop 3.3.6-5.0.1",
	"12225e325909cee70c31f5a7ab2ee194","ramaze-ruby (0.3.9.1)",
	"1275afc920a53a9679d2d0e8a5c74054","atlassian crowd",
	"127945e41f41073af7975fc828fd1808","the bodgeit store",
	"12888a39a499eb041ca42bf456aca285","atlassian confluence or crowd",
	"1391664373e72311a656c4a5504682af","jira",
	"140e3eb3e173bfb8d15778a578a213aa","bmpx (0.40.14)",
	"156515da3c0f7dc6b2493bd5ce43f795","nmap project",
	"171429057ae2d6ad68e2cd6dcfd4adc1","ebug-http (0.31)",
	"18fe76b96d4eae173bf439a9712fa5c1","wikiwebhelp",
	"192decdad41179599a776494efc3e720","jboss installation",
	"1a9a1ec2b8817a2f951c9f1793c9bc54","bitweaver",
	"1bf954ba2d568ec9771d35c94a6eb2dc","woltlab burning board",
	"1c4201c7da53d6c7e48251d3a9680449","nagios (3.0.2)",
	"1cc16c64d0e471607677b036b3f06b6e","roller weblogger project",
	"1cdecc190b122a232e64945332de0546","domainsponsor domain parking",
	"1ce0c63f8bd1e5d3376ec0ae95a41c08","parallels plesk panel",
	"1db747255c64a30f9236e9d929e986ca","parallels plesk",
	"1de863a5023e7e73f050a496e6b104ab","torrentflux (2.4)",
	"1f85f1f312825c87294a80c5bf9f0774","forministry church web hosting",
	"1f8c0b08fb6b556a6587517a8d5f290b","owasp.org",
	"1f9c39ef3f740eebb046c900edac4ba5","iomega storcenter ix2-200",
	"1fd3fafc1d461a3d19e91dbbba03d0aa","tea (17.6.1)",
	"20e208bb83f3eeed7c1aa8a6d9d3229d","libswarmcache-java (1.0rc2+cvs20071027)",
	"21d80d9730a56b26dc9d252ffabb2987","mythplugins (0.21.0+fixes18722)",
	"226ffc5e483b85ec261654fe255e60be","netscape enterprise server 4",
	"228ba3f6d946af4298b080e5c934487c","roundcube webmail 0.6-0.7 : default, 0.8-0.9 : classic, 0.8-0.9 : larry",
	"23426658f03969934b758b7eb9e8f602","chronicle (2.9) theme-steve",
	"237f837bbc33cd98a9f47b20b284e2ad","vdradmin-am (3.6.1)",
	"23e8c7bd78e8cd826c5a6073b15068b1","jenkins",
	"240c36cd118aa1ff59986066f21015d4","lancom systems",
	"24d1e355c00e79dc13b84d5455534fe7","kdelibs (3.5.10-4.1.4)",
	"2507c0b0a60ecdc816ba45482affaedf","webcheck (1.10.2.0)",
	"275e2e37fc7be50c1f03661ef8b6ce4f","myghty (1.1)",
	"27a097ec0dbffb7db436384635d50415","gforge (4.6.99+svn6496) - images",
	"27c3b07523efd6c318a201cac58008ba","cimg (1.2.0.1)",
	"28015fcdf84ca0d7d382394a82396927","nanoblogger (3.3)",
	"28893699241094742c3c2d4196cd1acb","xerox docushare",
	"28a122aa74f6929b0994fc544555c0b1","wordpress 3.2-3.x : twenty eleven",
	"28c34462a074c5311492759435549468","acontent",
	"292b586171617b56e77ee694485b1052","hover domain forwarding",
	"297d726681297cbf839f43a125e5c9b4","znc irc bouncer (web interface)",
	"29c923487a6d45e59ae802c3f2902738","elexio church cms",
	"2ab2aae806e8393b70970b2eaace82e0","couchdb (0.8.0-0.9.1)",
	"2b354dcd9968722567eaf374d6ed2132","apache",
	"2b52c1344164d29dd8fb758db16aadb6","vdr-plugin-live (0.2.0)",
	"2ba9b777483da0a6a8b29c4ab39a10b2","magicmail",
	"2c0067d9382a7f1751fed2d200f38db7","point2 agent real estate marketing",
	"2c338c26309e13987d315d85f499d7f2","e107 cms",
	"2cc15cfae55e2bb2d85b57e5b5bc3371","phpwiki (1.3.14) / gforge (4.6.99+svn6496) - wiki",
	"2d4cca83cf14d1adae178ad013bdf65b","ant docs manual (1.7.1)",
	"2df6edffca360b7a0fadc3bdf2191857","pips technology atz executive / automatic licence plate recognition (alpr) system",
	"2e5e985fe125e3f8fca988a86689b127","visec",
	"2e9545474ee33884b5fb8a9a0b8806dd","ampache",
	"300b5c3f134d7ec0bca862cf113149d8","tversity",
	"31aa07fe236ee504c890a61d1f7f0a97","apache2 (2.2.9) docs-manual",
	"31c16dd034e6985b4ba929e251200580","stephen turner analog (6.0)",
	"325472601571f31e1bf00674c368d335","transparent 1x1 gif",
	"32bf63ac2d3cfe82425ce8836c9ce87c","ikiwiki (2.56ubuntu1)",
	"3341c6d3c67ccdaeb7289180c741a965","atlassian confluence or crowd",
	"33b04fb9f2ec918f5f14b41527e77f6d","znc (0.058)",
	"3541a8ed03d7a4911679009961a82675","status.net",
	"35c5093c70b822d05219af50f95fc546","association of liberal democrat councillors web hosting",
	"3646670cac1e2afae1fe152f2fd8c118","voila web hosting",
	"368c15ac73f0096aa3daff8ff6f719f8","redaxscript 1.0-1.2.1",
	"376cbef2f074485f525bbf45dbfc2cba","hosteur web hosting",
	"37a99d2ddea8b49f701db457b9a8ffed","iomega storcenter ix4-200d",
	"3829c84b91013773dcc4b080e1829b8d","typepad blog hosting",
	"386211e5c0b7d92efabd41390e0fc250","sparkweb web-based collaboration client",
	"389a8816c5b87685de7d8d5fec96c85b","xoops cms",
	"39308a30527336e59d1d166d48c7742c","hewlett-packard hplip (2.8.7) - doc",
	"3995c585b76bd5aa67cb6385431d378a","horde-sam (0.1+cvs20080316) - silver",
	"39a1599714e68d8d9af295f8dc5ab314","apache",
	"3e7f8aa6768bba07751fe8570d7a244c","airwatch",
	"3e87f7b72db63dfb1700207d0ee0ec13","apache",
	"3ead5afa19537170bb980924397b70d6","wordpress 3.x : twenty ten",
	"3ef81fad2a3deaeb19f02c9cf67ed8eb","dokuwiki (0.0.20080505)",
	"4133fbad57c15caf3b18b9b65edcee76","html refresh",
	"41e2c893098b3ed9fc14b821a2e14e73","netscape 6.0 (aol)",
	"41e9c43dc5e994ca7a40f4f92b50d01d","hitachi",
	"421e176ae0837bcc6b879ef55adbc897","oracle",
	"428b23df874b41d904bbae29057bdba5","comsenz technology ltd ecshop",
	"42bb648e781be6baa099b76e75609126","apache",
	"43ba066789e749f9ef591dc086f3cd14","atlassian bamboo",
	"43d4aa56dc796067b442c95976a864fd","hunchentoot (0.15.7)",
	"45210ace96ce9c893f8c27c5decab10d","fritz!box",
	"462794b1165c44409861fcad7e185631","hercules (3.05)",
	"4644f2d45601037b8423d45e13194c93","apache tomcat (possibly 5.5.26 through 8.0.15)",
	"46b742e6ba5d7ac03f13b312601c113f","xbmc media center 12.x (web interface)",
	"48c02490ba335a159b99343b00decd87","octeth technologies oempro (3.5.5.1)",
	"4973c3c3067f8526ad0dacd2823b814e","adobe experience manager/cq5",
	"4987120f4fb1dc454f889e8c92f6dabe","google web server",
	"49bf194d1eccb1e5110957d14559d33d","otrs",
	"4afcc9582b28af45ce8a1312761d8d4c","apache",
	"4b2524b4f28eac7d0e872b0e1323c02d","meinberg",
	"4b30eec86e9910e663b5a9209e9593b6","phpldapadmin (1.1.0.5)",
	"4c3373870496151fd02a6f1185b0bb68","rpath appliance agent",
	"4cbb2cfc30a089b29cd06179f9cc82ff","dragonfly",
	"4ce0ca1e6361bf790a8386340bc2b90e","wackopicko.com",
	"4cfbb29d0d83685ba99323bc0d4d3513","phpwind forums 7",
	"4d7fe200d85000aea4d193a10e550d04","intland software codebeamer",
	"4e370f295b96eef85449c357aad90328","comsenz technology ltd supesite",
	"4eb846f1286ab4e7a399c851d7d84cca","plone cms (3.1.1)",
	"4ee75ca12a52425b9514ee6de25d23fe","hostmonster web hosting",
	"4f12cccd3c42a4a478f067337fe92794","cacti (0.8.7b)",
	"4f88ba9f1298701251180e6b6467d43e","xinit systems ltd. openfiler",
	"506190fc55ceaa132f1bc305ed8472ca","socialtext",
	"51b916bdaf994ce73d3e5e6dfe2a46ee","feng office 2.3",
	"531b63a51234bb06c9d77f219eb25553","phpmyadmin (4.6.x)",
	"531e652a15bc0ad59b6af05019b1834a","synology dsm 4.2",
	"54667bea91124121e98da49e55244935","kolab-webadmin (2.1.0-20070510)",
	"5488c1c8bf5a2264b8d4c8541e2d5ccd","turbogears (1.0.4.4) - genshi/elixir",
	"54b299f2f1c8b56c8c495f2ded6e3e0b","garlic-doc (1.6)",
	"56753c5386a70edba6190d49252f00bb","gallery (1.5.8)",
	"56974e6b57c7bd51448c309915ca0d6c","ghost blog (0.7.x)",
	"59a0c7b6e4848ccdabcea0636efda02b","blogger blog hosting",
	"5a77e47fa23554a4166d2303580b0733","sawmill",
	"5b015106854dc7be448c14b64867dfa5","tulip (3.0.0~b6)",
	"5b0e3b33aa166c88cee57f83de1d4e55","dotnetnuke cms",
	"5b816961f19da96ed5a2bf15e79093cb","atutor",
	"5c3e5bd042d8f70c68ba903b85ba7d2e","earthlink web hosting",
	"5d27143fc38439baba39ba5615cbe9ef","cascade server",
	"5d48c15b19222264f533c25943519861","apache",
	"5e1e9cc940d3bfaa59f51282d9fec510","free web hosting (free.fr)",
	"5e4fcc77c49e69b4f55aed91c05256f3","asus aicloud",
	"5e99522b02f6ecadbb3665202357d775","hplip (2.8.7) - installer",
	"5ec8d0ecf7b505bb04ab3ac81535e062","telligent community server",
	"5f09cded07bb864fd9b3d2dd72b5418e","twonkyserver premium 7.0.x",
	"5f6309ea0d1adeab12c18dc31be49771","reliance network real estate web hosting",
	"5f8b52715c08dfc7826dad181c71dec8","mahara (1.0.4)",
	"60fa7ed2309d77de1f9dc5e7c741ac48","sonicwall",
	"61e029c99abc5cf058abc77562a69f98","schoolcenter cms",
	"62e62d2311db890bf72e1069194074fd","the bodgeit store",
	"630b121c290442a00a95ae1196aa37ff","wz.cz web hosting",
	"63740175dae089e479a70c5e6591946c","the lyceum project",
	"6399cc480d494bf1fcd7d16c42b1c11b","penguin",
	"639b61409215d770a99667b446c80ea1","ibm lotus notes collaboration software",
	"63b982eddd64d44233baa25066db6bc1","joomla! cms",
	"63d5627fc659adfdd5b902ecafe9100f","gsoap (2.7.9l)",
	"6434232d43f27ef5462ba5ba345e03df","znc (0.058, webadmin/skins/default)",
	"64ca706a50715e421b6c2fa0b32ed7ec","parallels plesk control panel",
	"650b28c6cf1b473aed15ba26bad1da92","plesk obsidian",
	"663ee93a41000b8959d6145f0603f599","ldap-account-manager (2.3.0)",
	"669bc10baf11b43391294aac3e1b8c52","libitpp (4.0.4)",
	"66b3119d379aee26ba668fef49188dd3","cakephp 1.2.x-1.3.x application",
	"66dcdd811a7d8b1c7cd4e15cef9d4406","iomega storcenter px12-400r",
	"68b329da9893e34099c7d8ad5cb9c940","myghty (1.1) - zblog",
	"6900fab05a50a99d284405f46e5bc7f6","k3d (0.6.7.0)",
	"6927da350550f29bc641138825dff36f","python-werkzeug (0.3.1) - docs",
	"69acfcb2659952bc37c54108d52fca70","solr (1.2.0) - docs",
	"69ae01d0c74570d4d221e6c24a06d73b","roku soundbridge",
	"69c728902a3f1df75cf9eac73bd55556","damn vulnerable web app (dvwa) - login",
	"69f8a727f01a7e9b90a258bc30aaae6a","quantlib-refman-html (0.9.0)",
	"6acfee4c670580ebf06edae40631b946","iomega storcenter",
	"6be5ebd07e37d0b415ec83396a077312","ramaze-ruby (0.3.9.1) - dispatcher",
	"6c1452e18a09070c0b3ed85ce7cb3917","atlassian jira",
	"6c18a6e983f64b6a6ed0a32c9e8a19b6","hp procurve webserver",
	"6c4ec806c82ab04d6b7d857e6fb68f95","doteasy web hosting",
	"6c633b9b92530843c782664cb3f0542d","clipbucket",
	"6ca25bc6d278a0c6af66d2eecab1d0d6","getboo - get your bookmarks!",
	"6cec5a9c106d45e458fc680f70df91b0","wordpress - obsolete version",
	"6d2adf39ca320265830403dfc030033a","liferay portal",
	"6d85758acb4f4baa4d242ba451c91026","redmine x, request tracker",
	"6dcab71e60f0242907940f0fcda69ea5","ubiquiti ubiquiti m series / airos",
	"6e0c5b7979e9950125c71341e0960f65","phpsysinfo 3.0.8-3.0.12",
	"6eb4a43cb64c97f76562af703893c8fd","xampp",
	"6f767458b952d4755a795af0e4e0aa17","yahoo! web hosting",
	"6f7e92fe7e6a62661ac2b41528a78fc6","vlc (0.9.4)",
	"701bb703b31f99da18251ca2e557edf0","mantis bug tracker 1.2.9-1.2.15",
	"705d63d8f6f485bd40528394722b5c22","atmail",
	"70625a6e60529a85cc51ad7da2d5580d","sslstrip",
	"70777a39f5d1de6d3873ffb309df35dd","pathological (1.1.3)",
	"7194d8afd9e3a6dd0048149c3f66d60a","endurance international web hosting",
	"71e30c507ca3fa005e2d1322a5aa8fb2","apache on redhat",
	"71fa36961a58e12a525e7e0ea1f4a30d","about.com",
	"7214637a176079a335d7ac529011f4e4","phpress",
	"7350c3f75cb80e857efa88c2fd136da5","ushahidi",
	"73778a17b0d22ffbb7d6c445a7947b92","apache on mac os",
	"740af61c776a3cb98da3715bdf9d3fc1","vbulletin forum",
	"74120b5bbc7be340887466ff6cfe66c6","cups (1.3.9) - doc",
	"75069c2c6701b2be250c05ec494b1b31","chronicle (2.9) theme-blog.mail-scanning.com",
	"7513f4cf4802f546518f26ab5cfa1cad","axyl (2.6.0)",
	"7563f8c3ebd4fd4925f61df7d5ed8129","holger zimmerman pi3web http server",
	"75aeda7adbd012fa93c4ae80336b4f45","parrot (0.4.13) - docs",
	"773669c6c97d65ac5ede9e8ea6b47116","plex media server 0.9.x",
	"799f70b71314a7508326d1d2f68f7519","jboss server",
	"7a52b2a795dabe950e9dd2381ded8dc7","adobe crxde lite",
	"7b0d4bc0ca1659d54469e5013a08d240","netgear (infrant) readynas nv+",
	"7b345857204926b62951670cd17a08b7","axess tmc x1 or x2 terminal",
	"7c7b66d305e9377fa1fce9f9a74464d9","spe (0.8.4.h)",
	"7cc1a052c86cc3d487957f7092a6d8c3","horde (3.2.1) - graphics/tango",
	"7ceb7789d54a151fdc75c59925351b7b","chez.com web hosting",
	"7dbe9acc2ab6e64d59fa67637b1239df","ibm lotus domino collaboration software",
	"7e20c3f975ec430ac88e5863c0f48b23","countywebsite.com web hosting",
	"7ef1f0a0093460fe46bb691578c07c95","dedecms",
	"7f0f918a78ca8d4d5ff21ea84f2bac68","subtext",
	"7f57bbd0956976e797b4e8eebdc6d733","selfhtml (8.1.1)",
	"7ff45523a7ee9686d3d391a0a27a0b4f","qnap turbonas 4.0.x",
	"80656aabfafe0f3559f71bb0524c4bb3","macromedia breeze",
	"8190ead2eb45952151ab5065d0e56381","pootle (1.1.0)",
	"81df3601d6dc13cbc6bd8212ef50dd29","horde groupware webmail 1.0.1 (nag theme, 2.1.4)",
	"81ed5fa6453cf406d1d82233ba355b9a","e-zekiel church cms",
	"81edeec6e603d73d52bf85a3354fd093","jamf software/casper suite",
	"81feac35654318fb16d1a567b8b941e7","yaws (1.77)",
	"82d746eb54b78b5449fbd583fc046ab2","perl-doc-html (5.10.0)",
	"83245b21512cc0a0e7a67c72c3a3f501","openxpki",
	"835306119474fefb6b38ae314a37943a","horde agora (forum)",
	"83a1fd57a1e1684fafd6d2487290fdf5","pligg",
	"83dea3d5d8c6feddec84884522b61850","torrentflux (2.4) - themes/g4e/",
	"85138f44d577b03dfc738d3f27e04992","gitweb",
	"857281e82ea34abbb79b9b9c752e33d2","gforge (4.6.99+svn6496) - webcalendar",
	"868e7b460bba6fe29a37aa0ceff851ba","netmrg (0.20)",
	"86e3bf076a018a23c12354e512af3b9c","spyce",
	"8718c2998236c796896b725f264092ee","typo3 6.1",
	"8757fcbdbd83b0808955f6735078a287","comsenz technology ltd discuz!",
	"88644c0b60bf24b96d3d15f19196944e","ubee interactive cable modem",
	"88733ee53676a47fc354a61c32516e82","magento go cms",
	"8894791e84f5cafebd47311d14a3703c","joomla 1.7",
	"89b932fcc47cf4ca3faadb0cfdef89cf","hikvision dvr",
	"8a185957a6b153314bab3668b57f18f4","mobileiron",
	"8ab2f1a55bcb0cac227828afd5927d39","kdenetwork (4.1.4)",
	"8c291e32e7c7c65124d19eb17bceca87","schneider electric modicon 340 / bmx p34 cpu b",
	"8d13927efb22bbe7237fa64e858bb523","transmission (1.34)",
	"8d3fd22cab7ad1a6b10ae10e96143333","apache",
	"8dfab2d881ce47dc41459c6c0c652bcf","iomega storcenter px12-350r",
	"90c244c893a963e3bb193d6043a347bd","phpgroupware (0.9.16.012)",
	"9187f6607b402df8bbc2aeb69a07bbca","xoops",
	"919e132a62ea07fce13881470ba70293","horde groupware webmail 1.0.1 (ingo theme, 1.1.5)",
	"91b72b23e7f499d6c09cb18c7b1278f1","kodi media center 16.x (web interface)",
	"921042508f011ae477d5d91b2a90d03f","gonzui (1.2+cvs20070129)",
	"92c5d340d08c6d33676a41ba8dece857","android paw server",
	"92d0841188d40b6fef294cf53a8addd7","cpanel cpsrvd webmail server",
	"933a83c6e9e47bd1e38424f3789d121d","moodle (1.8.2, 1.9.x, multiple default themes)",
	"95103d0eabcd541527a86f23b636e794","wordpress multi-user (mu)",
	"9637ebd168435de51fea8193d2d89e39","oss-labs bt panel",
	"966e60f8eb85b7ea43a7b0095f3e2336","confluence",
	"9789c9ab400ea0b9ca8fcbd9952133bd","twiki (4.1.2) - webpreferences",
	"99306a52c76e19e3c298a46616c5899c","amule (2.2.2)",
	"9939a032a9845e4d931d14e08f5a6c7c","citrix xenapp logon",
	"9a8035769d7a129b19feb275a33dc5b4","ocsinventory-server (1.01)",
	"9a9ee243bc8d08dac4448a5177882ea9","dvbbs forum",
	"9afa5d60e5ef15dc75d7662e418cac72","qnap turbonas",
	"9c003f40e63df95a2b844c6b61448310","dd-wrt embedded web server",
	"9c34a7481ba0c153bb3e2a10e0ea811e","openwebif",
	"9ceae7a3c88fc451d59e24d8d5f6f166","plesk managed system",
	"9d203fbb74eabf67f48b965ba5acc9a6","iomega storcenter px4-300d",
	"9f500a24ccbdda88cf8ae3ec7b61fc40","atomic cms",
	"9f51fd640088904309551a473cbc525e","twitter",
	"9fac8b45400f794e0799d0d5458c092b","comsenz technology ltd discuz!",
	"a18421fbf34123c03fb8b3082e9d33c8","chora2 (2.0.2)",
	"a1c686eb6e771878cf6040574a175933","civicplus government web sites",
	"a1eadaf7974e7ce9889a5d7a07844590","outlook web app 2013-2019",
	"a2714be3e4c2f0ad16f33d3138033483","motorola esite builder (resin web server)",
	"a28ebcac852795fe30d8e99a23d377c1","sun one web server",
	"a2b03592bd74d3bf6b71a327a4b39ff6","apache",
	"a2e38a3b0cdf875cd79017dcaf4f2b55","sork-passwd-h3 (3.0)",
	"a31552d4fcc0ea68d69153e458fe6ab2","google page creator",
	"a34dea4bd04bdb816bea176619c29063","parallels confixx control panel",
	"a456dd2bae5746beb68814a5ac977048","phpsysinfo 3.0.7",
	"a46bc7fc42979e9b343335bdd86d1c3e","netscout ngenius",
	"a47951fb41640e7a2f5862c296e6f218","plone cms",
	"a4819787db1dabe1a6b669d5d6df3bfd","drupal 2.x-4.x",
	"a4eb4e0aa80740db8d7d951b6d63b2a2","owncloud",
	"a5220ef442813c2fc6ee8cf13560278f","republika web hosting",
	"a59c6fead5d55050674f327955df3acb","couchpotato 2.x",
	"a5b126cdeaa3081f77a22b3e43730942","horde groupware webmail 1.0.1 (kronolith theme, 2.1.8)",
	"a6b55b93bc01a6df076483b69039ba9c","fog creek fogbugz (6.1.44)",
	"a7947b1675701f2247921cf4c2b99a78","alexander palmo simple php blog",
	"a7fe149a9f2582f38576d14d9b1f0f55","lacie dashboard",
	"a83dfece1c0e9e3469588f418e1e4942","atlassian bamboo",
	"a8fe5b8ae2c445a33ac41b33ccc9a120","arris touchstone device",
	"a92054c4d5edc75ab9b8b3ce8bf0bcb6","hit.bg web hosting",
	"a967c8bfde9ea0869637294b679b7251","squid proxy server",
	"aa2253a32823c8a5cba8d479fecedd3a","sork-forwards-h3 (3.0.1)",
	"aa9b62c9aa50e0bc1f77061e6362d736","apache",
	"ab5fbb78e839bac0eee74787740475e8","apache",
	"abeea75cf3c1bac42bbd0e96803c72b9","doc-iana-20080601",
	"ae59960e866e2730e99799ac034eacf7","webcit (7.37)",
	"af83bba99d82ea47ca9dafc8341ec110","qwik (0.8.4.4ubuntu2)",
	"af999538cd3d4d0370f3ea92e0a6070f","h-sphere control panel",
	"b01625f4aa4cd64a180e46ef78f34877","quickplot (0.8.13)",
	"b14353fafda7c90fb1a2a214c195de50","weberp",
	"b231ad66a2a9b0eb06f72c4c88973039","wordpress",
	"b25dbe60830705d98ba3aaf0568c456a","netscape iplanet 6.0",
	"b3045c004dd765466e84bd057eaaa795","skype for business",
	"b4ef6b5f343c8df8fea454c04b2fd614","sourcefire http admin",
	"b6341dfc213100c61db4fb8775878cec","drupal 7.x",
	"b64a1155b80e0b06272f8b842b83fa57","horde ansel (photo manager)",
	"b6652d5d71f6f04a88a8443a8821510f","moodle (1.8.2, 1.9.x, cornflower theme, /theme/cornflower/favicon.ico)",
	"b7f98dd27febe36b7275f22ad73c5e84","moinmoin",
	"b88c0eedc72d3bf4e86c2aa0a6ba6f7b","nas4free 9.0",
	"b8fe2ec1fcc0477c0d0f00084d824071","lucene (2.3.2)",
	"b9d28bd6822d2e09e01aa0af5d7ccc34","ocportal 9.0.5",
	"ba4bfe5d1deb2b4410e9eb97c5b74c9b","puppet node manager",
	"ba84999dfc070065f37a082ab0e36017","prewikka (0.9.14)",
	"bba9f1c29f100d265865626541b20a50","dtc (0.28.10)",
	"bc18566dcc41a0ff503968f461c4995a","subrion cms",
	"bc96cb8d0841380f3504bb5584f78198","ekmpowershop web store",
	"bd0f7466d35e8ba6cedd9c27110c5c41","serena collage (4.6, servlet/images/collage_app.ico)",
	"bd9e17c46bbbc18af2a2bd718dddad0e","dvr? intelbras, maybe",
	"be6fb62815509bd707e69ee8dad874a1","i.lon server by echelon",
	"beeb88e064a874061e1fa8a3223b1c69","apache tomcat",
	"befcded36aec1e59ea624582fcb3225c","thomson/speedtouch device",
	"c0533ae5d0ed638ba3fb3485d8250a28","cakephp 1.1.x application",
	"c0c4e7c0ac4da24ab8fc842d7f96723c","xsp (1.9.1)",
	"c0dc2e457e05c2ce0a99886ec1048d77","platform computing corporation platform management console version v2.0",
	"c1201c47c81081c7f0930503cae7f71a","vbulletin forum",
	"c126f7e761813946fea2e90ff7ddb838","zenoss core",
	"c16b0a5c9eb3bfd831349739d89704ec","gramps (3.0.1)",
	"c1f20852dd1caf078f49de77a2de8e3f","vbulletin forum",
	"c30bf7e6d4afe1f02969e0f523d7a251","nulog (2.0)",
	"c5388dffab10da7531f94e7424be3394","fc2web web hosting",
	"c60ea375c39d1ab273c4d1bee717287a","synology diskstation manager",
	"c86974467c2ac7b6902189944f812b9a","domain technology control 0.17.x-0.24.x",
	"c9339a2ecde0980f40ba22c2d237b94b","glpi (0.70.2)",
	"c9856f0a4dd7ad0c215a68052a04d9e8","oracle",
	"ca5aeaaabc9019eb5ce8e03ec3bd809d","apache",
	"ca79aba701b8ed97d4505bcd766df6f3","parked.com domain parking",
	"cb740847c45ea3fbbd80308b9aa4530a","sork-vacation-h3 (3.0.1)",
	"ce16cde3e74e64131992da97b266ee95","livejournal blog hosting",
	"ceb25c12c147093dc93ac8b2c18bebff","compact 5020 voip",
	"ceddc34cbec02d74fe40368e2dc1fa90","mambo cms",
	"cee40c0b35bded5e11545be22a40e363","ossdl.de openmailadmin",
	"d00d85c8fb3a11170c1280c454398d51","ktorrent (3.1.2)",
	"d037ef2f629a22ddadcf438e6be7a325","phpmyadmin (2.11.8.1 - 4.2.x)",
	"d134378a39c722e941ac25eed91ca93b","freepbx",
	"d16a0da12074dae41980a6918d33f031","thomson/speedtouch 605 device",
	"d1bc9681dce4ad805c17bd1f0f5cee97","torrentflux (2.4) - themes/blueflux/",
	"d361075db94bb892ff3fb3717714b2da","phpmybackuppro",
	"d41d8cd98f00b204e9800998ecf8427e","zero byte favicon",
	"d4af3be33d952c1f98684d985019757c","moodle 2.0 : magazine",
	"d577e9569381685b30feae22484c8344","znc irc bouncer (web interface)",
	"d5fe5cbcc31cff5f8ac010db72eb000c","wordpress cms",
	"d6923071afcee9cebcebc785da40b226","autopsy (2.08)",
	"d6c8358104c64b2a3415f2f779c01ef2","google sites web hosting",
	"d7ac014e83b5c4a2dea76c50eaeda662","vbulletin forum",
	"d80e364c0d3138c7ecd75bf9896f2cad","apache tomcat (6.0.18), alfresco enterprise content management system",
	"d90cc1762bf724db71d6df86effab63c","vtiger crm",
	"d9aa63661d742d5f7c7300d02ac18d69","dreambox webcontrol",
	"dab7634e942aa927d100ca3b57795f72","interfree web hosting",
	"db1e3fe4a9ba1be201e913f9a401d794","gollem (1.0.3)",
	"dc0816f371699823e1e03e0078622d75","aruba network devices (http(s) login page)",
	"dcea02a5797ce9e36f19b7590752563e","parallels plesk panel",
	"ddcc65196f0bc63a90c885bd88ecbb81","phpsysinfo 3.0.12-3.0.20, 3.1.0-3.1.4",
	"ddd76f1cfe31499ce3db6702991cbc45","cream (0.41)",
	"de2b6edbf7930f5dd0ffe0528b2bbcf4","barracuda spam/virus firewall appliance",
	"de68f0ad7b37001b8241bce3887593c7","b2evolution (2.4.2)",
	"df055c65114b64b29ea68721fcdf9039","online.net web hosting",
	"e07c0775523271d629035dc8921dffc7","zoneminder (1.23.3)",
	"e08333841cbe40d15b18f49045f26614","21publish blog",
	"e16377344d2d52a15e735041b3eb2c5a","kibana/jenkins",
	"e19ffb2bc890f5bdca20f10bfddb288d","rapid7 (nexpose)",
	"e1e8bdc3ce87340ab6ebe467519cf245","bluehost/wordpress web hosting",
	"e223c25c0e0b2dbef4205fbf15b5f9bb","recipero schools.ik.org web hosting",
	"e298e00b2ff6340343ddf2fc6212010b","nessus 4.x scanner web client",
	"e2cac3fad9fa3388f639546f3ba09bc0","invision power services ip.board",
	"e2f638a6572e9270ac73402f6481425b","apache",
	"e3f28aab904e9edfd015f64dc93d487d","python-werkzeug (0.3.1) - cupoftee-examples",
	"e44d22b74f7ee4435e22062d5adf4a6a","wordpress 2.x",
	"e462005902f81094ab3de44e4381de19","fortinet",
	"e4a509e78afca846cd0e6c0672797de5","i3micro vrg",
	"e52c40433aa5f9256e521d7c139a05bd","avenet web hosting",
	"e551b7017a9bd490fc5b76e833d689bf","moinmoin (1.7.1)",
	"e6a9dc66179d8c9f34288b16a02f987e","drupal cms",
	"e738f22aab002bd66350d1b2d930e9a9","apache",
	"e7dce6ac6d8713a0b98407254ca33f80","iomega storcenter ix4-300d",
	"e7fc436d0bf31500ced7a7143067c337","twiki (4.1.2) - logos/favicon.ico",
	"e81c59b85762d7db2ac7f83b2d5cd521","wackopicko.com",
	"e9469705a8ac323e403d74c11425a62b","roundcube (0.1.1)",
	"e9dd9992d222d67c8f6a4704d2c88bdd","zarafa webaccess",
	"e9e6c56f63122fb05e6899e1dedd0734","worldsoft cms",
	"ea84a69cb146a947fac2ac7af3946297","boost (1.34.1)",
	"eb05f77bf80d66f0db6b1f682ff08bee","biscom delivery server",
	"eb3e307f44581916d9f1197df2fc9de3","flac (1.2.1)",
	"eb6d4ce00ec36af7d439ebd4e5a395d7","mailman",
	"ebe293e1746858d2548bca99c43e4969","mantis bug tracker (1.1.2, /bugs/images/favicon.ico)",
	"ec49973c1991bf39fcdb53260467f39f","parallels control panel",
	"ecaa88f7fa0bf610a5a26cf545dcd3aa","3-byte invalid favicon: domain sellers",
	"ecab73f909ddd28e482ababe810447c8","gosa (2.5.16.1)",
	"ed7d5c39c69262f4ba95418d4f909b10","jetty (5.1.14)",
	"ed8cf53ef6836184587ee3a987be074a","ruckus",
	"edaaef7bbd3072a3a0c3fb3b29900bcb","reynolds webmakerx auto sales cms",
	"ee1169dee71a0a53c91f5065295004b7","projectpier",
	"ee3d6a9227e27a5bc72db3184dab8303","horde-sam (0.1+cvs20080316) - graphics",
	"ee4a637a1257b2430649d6750cda6eba","trimble device embedded web server",
	"eec3051d5c356d1798bea1d8a3617c51","octopress",
	"ef5169b040925a716359d131afbea033","websvn (2.0)",
	"ef9c0362bf20a086bb7c2e8ea346b9f0","roundcube webmail 1.0.0+, skins classic and larry",
	"f08d232927ab8f2c661616b896928233","iomega storcenter px2-300d",
	"f08df8e5de871525d8467e9514174448","cortix web hosting",
	"f097f0adf2b9e95a972d21e5e5ab746d","citrix access server",
	"f0ee98b4394dfdab17c16245dd799204","drupal",
	"f1876a80546b3986dbb79bad727b0374","netscreen webui or 3com router",
	"f1ac749564d5ba793550ec6bdc472e7c","roundcube webmail 1.4.0+, elastic skin",
	"f276b19aabcb4ae8cda4d22625c6735f","cgiirc (0.5.9)",
	"f30b5ed270a57eabea60beb935e2b800","fc2 blog hosting",
	"f3418a443e7d841097c714d69ec4bcb8","google",
	"f425342764f8c356479d05daa7013c2f","vbulletin forum",
	"f51425ace97f807fe5840c4382580fd5","beehive forum 1.x",
	"f567fd4927f9693a7a2d6cacf21b51b6","horde imp (4.1.4 - 4.1.6, also used in horde groupware webmail 1.0.1))",
	"f5f2df7eec0d1c3c10b58960f3f8fb26","horde groupware webmail 1.0.1 (mnemo theme, 2.1.2)",
	"f682dbd4d0a18dd7699339b8adb28c0f","qnap turbonas 3.8.x : admin",
	"f6c5f5e8857ecf561029fc5da005b6e3","sophos email appliance",
	"f6d0a100b6dbeb5899f0975a1203fd85","witty (2.1.5)",
	"f6e9339e652b8655d4e26f3e947cf212","egroupware (1.0.0.009, 1.4.004-2) (/phpgwapi/templates/idots/images/favicon.ico)",
	"f89abd3f358cb964d6b753a5a9da49cf","limesurvey",
	"f972c37bf444fb1925a2c97812e2c1eb","mediatomb (0.11.0)",
	"fa21ab1b1e1b4c9516afbd63e91275a9","lastfmproxy (1.3b)",
	"fa2b274fab800af436ee688e97da4ac4","etherpad",
	"fa339f101f0c0d65ee46cb96a06c8f45","sidearm athletics cms",
	"fa54dbf2f61bd2e0188e47f5f578f736","wordpress cms",
	"fbd140da4eff02b90c9ebcbdb3736322","iomega storcenter px4-300r",
	"fc4f0fca3dc008655feb2563fa7bbdd2","apache",
	"fd3f689b804ddb7bfab53fdf32bf7c04","iomega storcenter px6-300d",
	"fdc1a6aa785111bf77a811adeb0df4b0","dealerskins auto sales web hosting",
	"ff260e80f5f9ca4b779fbd34087f13cf","horde groupware webmail 1.0.1 (turba theme, 2.1.7)",
	"ff2c8612b75b5f9a6175e016fe4aa609","apache on linux",
	"ff3b533b061cee7cfbca693cc362c34a","kayako supportsuite",
	"ffc05799dee87a4f8901c458f7291d73","solr (1.2.0) - admin"
};