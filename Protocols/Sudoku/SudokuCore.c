#include "SudokuCore.h"

#include <ctype.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__APPLE__) && !defined(SUDOKU_LOCAL_OPENSSL_BACKEND)
#  define SUDOKU_CORE_USE_OPENSSL 0
#else
#  if defined(__has_include)
#    if __has_include(<openssl/evp.h>) && __has_include(<openssl/sha.h>)
#      define SUDOKU_CORE_USE_OPENSSL 1
#    endif
#  endif
#  ifndef SUDOKU_CORE_USE_OPENSSL
#    define SUDOKU_CORE_USE_OPENSSL 0
#  endif
#endif

#if SUDOKU_CORE_USE_OPENSSL
#  include <openssl/evp.h>
#  include <openssl/sha.h>
#else
#  include <CommonCrypto/CommonDigest.h>
#endif

#define SUDOKU_GRID_COUNT 288
#define SUDOKU_HINT_POSITION_COUNT 1820
#define SUDOKU_PROB_ONE ((uint64_t)1u << 32)

typedef struct {
    int tap;
    int feed;
    int64_t vec[607];
} sudoku_go_source_t;

static const uint8_t sudoku_perm4[24][4] = {
    {0, 1, 2, 3}, {0, 1, 3, 2}, {0, 2, 1, 3}, {0, 2, 3, 1},
    {0, 3, 1, 2}, {0, 3, 2, 1}, {1, 0, 2, 3}, {1, 0, 3, 2},
    {1, 2, 0, 3}, {1, 2, 3, 0}, {1, 3, 0, 2}, {1, 3, 2, 0},
    {2, 0, 1, 3}, {2, 0, 3, 1}, {2, 1, 0, 3}, {2, 1, 3, 0},
    {2, 3, 0, 1}, {2, 3, 1, 0}, {3, 0, 1, 2}, {3, 0, 2, 1},
    {3, 1, 0, 2}, {3, 1, 2, 0}, {3, 2, 0, 1}, {3, 2, 1, 0},
};

static const int64_t sudoku_go_rng_cooked[607] = {
    -4181792142133755926LL, -4576982950128230565LL, 1395769623340756751LL, 5333664234075297259LL,
    -6347679516498800754LL, 9033628115061424579LL, 7143218595135194537LL, 4812947590706362721LL,
    7937252194349799378LL, 5307299880338848416LL, 8209348851763925077LL, -7107630437535961764LL,
    4593015457530856296LL, 8140875735541888011LL, -5903942795589686782LL, -603556388664454774LL,
    -7496297993371156308LL, 113108499721038619LL, 4569519971459345583LL, -4160538177779461077LL,
    -6835753265595711384LL, -6507240692498089696LL, 6559392774825876886LL, 7650093201692370310LL,
    7684323884043752161LL, -8965504200858744418LL, -2629915517445760644LL, 271327514973697897LL,
    -6433985589514657524LL, 1065192797246149621LL, 3344507881999356393LL, -4763574095074709175LL,
    7465081662728599889LL, 1014950805555097187LL, -4773931307508785033LL, -5742262670416273165LL,
    2418672789110888383LL, 5796562887576294778LL, 4484266064449540171LL, 3738982361971787048LL,
    -4699774852342421385LL, 10530508058128498LL, -589538253572429690LL, -6598062107225984180LL,
    8660405965245884302LL, 10162832508971942LL, -2682657355892958417LL, 7031802312784620857LL,
    6240911277345944669LL, 831864355460801054LL, -1218937899312622917LL, 2116287251661052151LL,
    2202309800992166967LL, 9161020366945053561LL, 4069299552407763864LL, 4936383537992622449LL,
    457351505131524928LL, -8881176990926596454LL, -6375600354038175299LL, -7155351920868399290LL,
    4368649989588021065LL, 887231587095185257LL, -3659780529968199312LL, -2407146836602825512LL,
    5616972787034086048LL, -751562733459939242LL, 1686575021641186857LL, -5177887698780513806LL,
    -4979215821652996885LL, -1375154703071198421LL, 5632136521049761902LL, -8390088894796940536LL,
    -193645528485698615LL, -5979788902190688516LL, -4907000935050298721LL, -285522056888777828LL,
    -2776431630044341707LL, 1679342092332374735LL, 6050638460742422078LL, -2229851317345194226LL,
    -1582494184340482199LL, 5881353426285907985LL, 812786550756860885LL, 4541845584483343330LL,
    -6497901820577766722LL, 4980675660146853729LL, -4012602956251539747LL, -329088717864244987LL,
    -2896929232104691526LL, 1495812843684243920LL, -2153620458055647789LL, 7370257291860230865LL,
    -2466442761497833547LL, 4706794511633873654LL, -1398851569026877145LL, 8549875090542453214LL,
    -9189721207376179652LL, -7894453601103453165LL, 7297902601803624459LL, 1011190183918857495LL,
    -6985347000036920864LL, 5147159997473910359LL, -8326859945294252826LL, 2659470849286379941LL,
    6097729358393448602LL, -7491646050550022124LL, -5117116194870963097LL, -896216826133240300LL,
    -745860416168701406LL, 5803876044675762232LL, -787954255994554146LL, -3234519180203704564LL,
    -4507534739750823898LL, -1657200065590290694LL, 505808562678895611LL, -4153273856159712438LL,
    -8381261370078904295LL, 572156825025677802LL, 1791881013492340891LL, 3393267094866038768LL,
    -5444650186382539299LL, 2352769483186201278LL, -7930912453007408350LL, -325464993179687389LL,
    -3441562999710612272LL, -6489413242825283295LL, 5092019688680754699LL, -227247482082248967LL,
    4234737173186232084LL, 5027558287275472836LL, 4635198586344772304LL, -536033143587636457LL,
    5907508150730407386LL, -8438615781380831356LL, 972392927514829904LL, -3801314342046600696LL,
    -4064951393885491917LL, -174840358296132583LL, 2407211146698877100LL, -1640089820333676239LL,
    3940796514530962282LL, -5882197405809569433LL, 3095313889586102949LL, -1818050141166537098LL,
    5832080132947175283LL, 7890064875145919662LL, 8184139210799583195LL, -8073512175445549678LL,
    -7758774793014564506LL, -4581724029666783935LL, 3516491885471466898LL, -8267083515063118116LL,
    6657089965014657519LL, 5220884358887979358LL, 1796677326474620641LL, 5340761970648932916LL,
    1147977171614181568LL, 5066037465548252321LL, 2574765911837859848LL, 1085848279845204775LL,
    -5873264506986385449LL, 6116438694366558490LL, 2107701075971293812LL, -7420077970933506541LL,
    2469478054175558874LL, -1855128755834809824LL, -5431463669011098282LL, -9038325065738319171LL,
    -6966276280341336160LL, 7217693971077460129LL, -8314322083775271549LL, 7196649268545224266LL,
    -3585711691453906209LL, -5267827091426810625LL, 8057528650917418961LL, -5084103596553648165LL,
    -2601445448341207749LL, -7850010900052094367LL, 6527366231383600011LL, 3507654575162700890LL,
    9202058512774729859LL, 1954818376891585542LL, -2582991129724600103LL, 8299563319178235687LL,
    -5321504681635821435LL, 7046310742295574065LL, -2376176645520785576LL, -7650733936335907755LL,
    8850422670118399721LL, 3631909142291992901LL, 5158881091950831288LL, -6340413719511654215LL,
    4763258931815816403LL, 6280052734341785344LL, -4979582628649810958LL, 2043464728020827976LL,
    -2678071570832690343LL, 4562580375758598164LL, 5495451168795427352LL, -7485059175264624713LL,
    553004618757816492LL, 6895160632757959823LL, -989748114590090637LL, 7139506338801360852LL,
    -672480814466784139LL, 5535668688139305547LL, 2430933853350256242LL, -3821430778991574732LL,
    -1063731997747047009LL, -3065878205254005442LL, 7632066283658143750LL, 6308328381617103346LL,
    3681878764086140361LL, 3289686137190109749LL, 6587997200611086848LL, 244714774258135476LL,
    -5143583659437639708LL, 8090302575944624335LL, 2945117363431356361LL, -8359047641006034763LL,
    3009039260312620700LL, -793344576772241777LL, 401084700045993341LL, -1968749590416080887LL,
    4707864159563588614LL, -3583123505891281857LL, -3240864324164777915LL, -5908273794572565703LL,
    -3719524458082857382LL, -5281400669679581926LL, 8118566580304798074LL, 3839261274019871296LL,
    7062410411742090847LL, -8481991033874568140LL, 6027994129690250817LL, -6725542042704711878LL,
    -2971981702428546974LL, -7854441788951256975LL, 8809096399316380241LL, 6492004350391900708LL,
    2462145737463489636LL, -8818543617934476634LL, -5070345602623085213LL, -8961586321599299868LL,
    -3758656652254704451LL, -8630661632476012791LL, 6764129236657751224LL, -709716318315418359LL,
    -3403028373052861600LL, -8838073512170985897LL, -3999237033416576341LL, -2920240395515973663LL,
    -2073249475545404416LL, 368107899140673753LL, -6108185202296464250LL, -6307735683270494757LL,
    4782583894627718279LL, 6718292300699989587LL, 8387085186914375220LL, 3387513132024756289LL,
    4654329375432538231LL, -292704475491394206LL, -3848998599978456535LL, 7623042350483453954LL,
    7725442901813263321LL, 9186225467561587250LL, -5132344747257272453LL, -6865740430362196008LL,
    2530936820058611833LL, 1636551876240043639LL, -3658707362519810009LL, 1452244145334316253LL,
    -7161729655835084979LL, -7943791770359481772LL, 9108481583171221009LL, -3200093350120725999LL,
    5007630032676973346LL, 2153168792952589781LL, 6720334534964750538LL, -3181825545719981703LL,
    3433922409283786309LL, 2285479922797300912LL, 3110614940896576130LL, -2856812446131932915LL,
    -3804580617188639299LL, 7163298419643543757LL, 4891138053923696990LL, 580618510277907015LL,
    1684034065251686769LL, 4429514767357295841LL, -8893025458299325803LL, -8103734041042601133LL,
    7177515271653460134LL, 4589042248470800257LL, -1530083407795771245LL, 143607045258444228LL,
    246994305896273627LL, -8356954712051676521LL, 6473547110565816071LL, 3092379936208876896LL,
    2058427839513754051LL, -4089587328327907870LL, 8785882556301281247LL, -3074039370013608197LL,
    -637529855400303673LL, 6137678347805511274LL, -7152924852417805802LL, 5708223427705576541LL,
    -3223714144396531304LL, 4358391411789012426LL, 325123008708389849LL, 6837621693887290924LL,
    4843721905315627004LL, -3212720814705499393LL, -3825019837890901156LL, 4602025990114250980LL,
    1044646352569048800LL, 9106614159853161675LL, -8394115921626182539LL, -4304087667751778808LL,
    2681532557646850893LL, 3681559472488511871LL, -3915372517896561773LL, -2889241648411946534LL,
    -6564663803938238204LL, -8060058171802589521LL, 581945337509520675LL, 3648778920718647903LL,
    -4799698790548231394LL, -7602572252857820065LL, 220828013409515943LL, -1072987336855386047LL,
    4287360518296753003LL, -4633371852008891965LL, 5513660857261085186LL, -2258542936462001533LL,
    -8744380348503999773LL, 8746140185685648781LL, 228500091334420247LL, 1356187007457302238LL,
    3019253992034194581LL, 3152601605678500003LL, -8793219284148773595LL, 5559581553696971176LL,
    4916432985369275664LL, -8559797105120221417LL, -5802598197927043732LL, 2868348622579915573LL,
    -7224052902810357288LL, -5894682518218493085LL, 2587672709781371173LL, -7706116723325376475LL,
    3092343956317362483LL, -5561119517847711700LL, 972445599196498113LL, -1558506600978816441LL,
    1708913533482282562LL, -2305554874185907314LL, -6005743014309462908LL, -6653329009633068701LL,
    -483583197311151195LL, 2488075924621352812LL, -4529369641467339140LL, -4663743555056261452LL,
    2997203966153298104LL, 1282559373026354493LL, 240113143146674385LL, 8665713329246516443LL,
    628141331766346752LL, -4651421219668005332LL, -7750560848702540400LL, 7596648026010355826LL,
    -3132152619100351065LL, 7834161864828164065LL, 7103445518877254909LL, 4390861237357459201LL,
    -4780718172614204074LL, -319889632007444440LL, 622261699494173647LL, -3186110786557562560LL,
    -8718967088789066690LL, -1948156510637662747LL, -8212195255998774408LL, -7028621931231314745LL,
    2623071828615234808LL, -4066058308780939700LL, -5484966924888173764LL, -6683604512778046238LL,
    -6756087640505506466LL, 5256026990536851868LL, 7841086888628396109LL, 6640857538655893162LL,
    -8021284697816458310LL, -7109857044414059830LL, -1689021141511844405LL, -4298087301956291063LL,
    -4077748265377282003LL, -998231156719803476LL, 2719520354384050532LL, 9132346697815513771LL,
    4332154495710163773LL, -2085582442760428892LL, 6994721091344268833LL, -2556143461985726874LL,
    -8567931991128098309LL, 59934747298466858LL, -3098398008776739403LL, -265597256199410390LL,
    2332206071942466437LL, -7522315324568406181LL, 3154897383618636503LL, -7585605855467168281LL,
    -6762850759087199275LL, 197309393502684135LL, -8579694182469508493LL, 2543179307861934850LL,
    4350769010207485119LL, -4468719947444108136LL, -7207776534213261296LL, -1224312577878317200LL,
    4287946071480840813LL, 8362686366770308971LL, 6486469209321732151LL, -5605644191012979782LL,
    -1669018511020473564LL, 4450022655153542367LL, -7618176296641240059LL, -3896357471549267421LL,
    -4596796223304447488LL, -6531150016257070659LL, -8982326463137525940LL, -4125325062227681798LL,
    -1306489741394045544LL, -8338554946557245229LL, 5329160409530630596LL, 7790979528857726136LL,
    4955070238059373407LL, -4304834761432101506LL, -6215295852904371179LL, 3007769226071157901LL,
    -6753025801236972788LL, 8928702772696731736LL, 7856187920214445904LL, -4748497451462800923LL,
    7900176660600710914LL, -7082800908938549136LL, -6797926979589575837LL, -6737316883512927978LL,
    4186670094382025798LL, 1883939007446035042LL, -414705992779907823LL, 3734134241178479257LL,
    4065968871360089196LL, 6953124200385847784LL, -7917685222115876751LL, -7585632937840318161LL,
    -5567246375906782599LL, -5256612402221608788LL, 3106378204088556331LL, -2894472214076325998LL,
    4565385105440252958LL, 1979884289539493806LL, -6891578849933910383LL, 3783206694208922581LL,
    8464961209802336085LL, 2843963751609577687LL, 3030678195484896323LL, -4429654462759003204LL,
    4459239494808162889LL, 402587895800087237LL, 8057891408711167515LL, 4541888170938985079LL,
    1042662272908816815LL, -3666068979732206850LL, 2647678726283249984LL, 2144477441549833761LL,
    -3417019821499388721LL, -2105601033380872185LL, 5916597177708541638LL, -8760774321402454447LL,
    8833658097025758785LL, 5970273481425315300LL, 563813119381731307LL, -6455022486202078793LL,
    1598828206250873866LL, -4016978389451217698LL, -2988328551145513985LL, -6071154634840136312LL,
    8469693267274066490LL, 125672920241807416LL, -3912292412830714870LL, -2559617104544284221LL,
    -486523741806024092LL, -4735332261862713930LL, 5923302823487327109LL, -9082480245771672572LL,
    -1808429243461201518LL, 7990420780896957397LL, 4317817392807076702LL, 3625184369705367340LL,
    -6482649271566653105LL, -3480272027152017464LL, -3225473396345736649LL, -368878695502291645LL,
    -3981164001421868007LL, -8522033136963788610LL, 7609280429197514109LL, 3020985755112334161LL,
    -2572049329799262942LL, 2635195723621160615LL, 5144520864246028816LL, -8188285521126945980LL,
    1567242097116389047LL, 8172389260191636581LL, -2885551685425483535LL, -7060359469858316883LL,
    -6480181133964513127LL, -7317004403633452381LL, 6011544915663598137LL, 5932255307352610768LL,
    2241128460406315459LL, -8327867140638080220LL, 3094483003111372717LL, 4583857460292963101LL,
    9079887171656594975LL, -384082854924064405LL, -3460631649611717935LL, 4225072055348026230LL,
    -7385151438465742745LL, 3801620336801580414LL, -399845416774701952LL, -7446754431269675473LL,
    7899055018877642622LL, 5421679761463003041LL, 5521102963086275121LL, -4975092593295409910LL,
    8735487530905098534LL, -7462844945281082830LL, -2080886987197029914LL, -1000715163927557685LL,
    -4253840471931071485LL, -5828896094657903328LL, 6424174453260338141LL, 359248545074932887LL,
    -5949720754023045210LL, -2426265837057637212LL, 3030918217665093212LL, -9077771202237461772LL,
    -3186796180789149575LL, 740416251634527158LL, -2142944401404840226LL, 6951781370868335478LL,
    399922722363687927LL, -8928469722407522623LL, -1378421100515597285LL, -8343051178220066766LL,
    -3030716356046100229LL, -8811767350470065420LL, 9026808440365124461LL, 6440783557497587732LL,
    4615674634722404292LL, 539897290441580544LL, 2096238225866883852LL, 8751955639408182687LL,
    -7316147128802486205LL, 7381039757301768559LL, 6157238513393239656LL, -1473377804940618233LL,
    8629571604380892756LL, 5280433031239081479LL, 7101611890139813254LL, 2479018537985767835LL,
    7169176924412769570LL, -1281305539061572506LL, -7865612307799218120LL, 2278447439451174845LL,
    3625338785743880657LL, 6477479539006708521LL, 8976185375579272206LL, -3712000482142939688LL,
    1326024180520890843LL, 7537449876596048829LL, 5464680203499696154LL, 3189671183162196045LL,
    6346751753565857109LL, -8982212049534145501LL, -6127578587196093755LL, -245039190118465649LL,
    -6320577374581628592LL, 7208698530190629697LL, 7276901792339343736LL, -7490986807540332668LL,
    4133292154170828382LL, 2918308698224194548LL, -7703910638917631350LL, -3929437324238184044LL,
    -4300543082831323144LL, -6344160503358350167LL, 5896236396443472108LL, -758328221503023383LL,
    -1894351639983151068LL, -307900319840287220LL, -6278469401177312761LL, -2171292963361310674LL,
    8382142935188824023LL, 9103922860780351547LL, 4152330101494654406LL
};

static sudoku_grid_t sudoku_all_grids[SUDOKU_GRID_COUNT];
static uint8_t sudoku_hint_positions[SUDOKU_HINT_POSITION_COUNT][4];
static pthread_once_t sudoku_tables_once = PTHREAD_ONCE_INIT;

static void sudoku_build_hint_positions(void) {
    size_t idx = 0;
    int a, b, c, d;
    for (a = 0; a < 13; ++a) {
        for (b = a + 1; b < 14; ++b) {
            for (c = b + 1; c < 15; ++c) {
                for (d = c + 1; d < 16; ++d) {
                    sudoku_hint_positions[idx][0] = (uint8_t)a;
                    sudoku_hint_positions[idx][1] = (uint8_t)b;
                    sudoku_hint_positions[idx][2] = (uint8_t)c;
                    sudoku_hint_positions[idx][3] = (uint8_t)d;
                    idx++;
                }
            }
        }
    }
}

static int sudoku_grid_valid(const sudoku_grid_t *g, int idx, uint8_t num) {
    int row = idx / 4;
    int col = idx % 4;
    int br = (row / 2) * 2;
    int bc = (col / 2) * 2;
    int i, r, c;
    for (i = 0; i < 4; ++i) {
        if (g->cells[row * 4 + i] == num || g->cells[i * 4 + col] == num) {
            return 0;
        }
    }
    for (r = 0; r < 2; ++r) {
        for (c = 0; c < 2; ++c) {
            if (g->cells[(br + r) * 4 + (bc + c)] == num) {
                return 0;
            }
        }
    }
    return 1;
}

static void sudoku_generate_grids_rec(sudoku_grid_t *cur, int idx, size_t *out_idx) {
    uint8_t num;
    if (idx == 16) {
        sudoku_all_grids[*out_idx] = *cur;
        (*out_idx)++;
        return;
    }
    for (num = 1; num <= 4; ++num) {
        if (!sudoku_grid_valid(cur, idx, num)) {
            continue;
        }
        cur->cells[idx] = num;
        sudoku_generate_grids_rec(cur, idx + 1, out_idx);
        cur->cells[idx] = 0;
    }
}

static void sudoku_build_static_tables(void) {
    sudoku_grid_t g;
    size_t idx = 0;
    memset(&g, 0, sizeof(g));
    sudoku_generate_grids_rec(&g, 0, &idx);
    sudoku_build_hint_positions();
}

static int32_t sudoku_seedrand(int32_t x) {
    const int32_t A = 48271;
    const int32_t Q = 44488;
    const int32_t R = 3399;
    int32_t hi = x / Q;
    int32_t lo = x % Q;
    x = A * lo - R * hi;
    if (x < 0) {
        x += 2147483647;
    }
    return x;
}

static void sudoku_go_source_seed(sudoku_go_source_t *rng, int64_t seed) {
    int i;
    int32_t x;
    rng->tap = 0;
    rng->feed = 607 - 273;
    seed %= 2147483647;
    if (seed < 0) {
        seed += 2147483647;
    }
    if (seed == 0) {
        seed = 89482311;
    }
    x = (int32_t)seed;
    for (i = -20; i < 607; ++i) {
        int64_t u;
        x = sudoku_seedrand(x);
        if (i < 0) {
            continue;
        }
        u = ((int64_t)x) << 40;
        x = sudoku_seedrand(x);
        u ^= ((int64_t)x) << 20;
        x = sudoku_seedrand(x);
        u ^= (int64_t)x;
        u ^= sudoku_go_rng_cooked[i];
        rng->vec[i] = u;
    }
}

static uint64_t sudoku_go_source_u64(sudoku_go_source_t *rng) {
    int64_t x;
    rng->tap--;
    if (rng->tap < 0) {
        rng->tap += 607;
    }
    rng->feed--;
    if (rng->feed < 0) {
        rng->feed += 607;
    }
    x = rng->vec[rng->feed] + rng->vec[rng->tap];
    rng->vec[rng->feed] = x;
    return (uint64_t)x;
}

static int32_t sudoku_go_int31n(sudoku_go_source_t *rng, int32_t n) {
    uint64_t x = sudoku_go_source_u64(rng) & 0x7fffffffffffffffULL;
    uint32_t v = (uint32_t)(x >> 31);
    uint64_t prod = (uint64_t)v * (uint64_t)n;
    uint32_t low = (uint32_t)prod;
    if (low < (uint32_t)n) {
        uint32_t thresh = (uint32_t)(-n) % (uint32_t)n;
        while (low < thresh) {
            x = sudoku_go_source_u64(rng) & 0x7fffffffffffffffULL;
            v = (uint32_t)(x >> 31);
            prod = (uint64_t)v * (uint64_t)n;
            low = (uint32_t)prod;
        }
    }
    return (int32_t)(prod >> 32);
}

static void sudoku_go_shuffle_grids(sudoku_grid_t *grids, size_t n, int64_t seed) {
    sudoku_go_source_t rng;
    size_t i;
    sudoku_go_source_seed(&rng, seed);
    if (n == 0) {
        return;
    }
    for (i = n - 1; i > 0; --i) {
        int j = sudoku_go_int31n(&rng, (int32_t)(i + 1));
        sudoku_grid_t tmp = grids[i];
        grids[i] = grids[j];
        grids[j] = tmp;
    }
}

void sudoku_splitmix64_seed(sudoku_splitmix64_t *rng, int64_t seed) {
    uint64_t state = (uint64_t)seed;
    if (!state) {
        state = 0x9e3779b97f4a7c15ULL;
    }
    rng->state = state;
}

uint64_t sudoku_splitmix64_next_u64(sudoku_splitmix64_t *rng) {
    uint64_t z;
    rng->state += 0x9e3779b97f4a7c15ULL;
    z = rng->state;
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
    return z ^ (z >> 31);
}

uint32_t sudoku_splitmix64_next_u32(sudoku_splitmix64_t *rng) {
    return (uint32_t)(sudoku_splitmix64_next_u64(rng) >> 32);
}

int sudoku_splitmix64_intn(sudoku_splitmix64_t *rng, int n) {
    if (n <= 1) {
        return 0;
    }
    return (int)(((uint64_t)sudoku_splitmix64_next_u32(rng) * (uint64_t)n) >> 32);
}

uint64_t sudoku_pick_padding_threshold(sudoku_splitmix64_t *rng, int pmin, int pmax) {
    uint64_t minv, maxv, u;
    if (pmin < 0) pmin = 0;
    if (pmax < pmin) pmax = pmin;
    if (pmin > 100) pmin = 100;
    if (pmax > 100) pmax = 100;
    minv = ((uint64_t)pmin * SUDOKU_PROB_ONE) / 100;
    maxv = ((uint64_t)pmax * SUDOKU_PROB_ONE) / 100;
    if (maxv <= minv) {
        return minv;
    }
    u = sudoku_splitmix64_next_u32(rng);
    return minv + ((u * (maxv - minv)) >> 32);
}

int sudoku_should_pad(sudoku_splitmix64_t *rng, uint64_t threshold) {
    if (threshold == 0) {
        return 0;
    }
    if (threshold >= SUDOKU_PROB_ONE) {
        return 1;
    }
    return ((uint64_t)sudoku_splitmix64_next_u32(rng)) < threshold;
}

static uint32_t sudoku_pack_hints(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
    uint8_t h[4] = {a, b, c, d};
    uint8_t tmp;
    if (h[0] > h[1]) { tmp = h[0]; h[0] = h[1]; h[1] = tmp; }
    if (h[2] > h[3]) { tmp = h[2]; h[2] = h[3]; h[3] = tmp; }
    if (h[0] > h[2]) { tmp = h[0]; h[0] = h[2]; h[2] = tmp; }
    if (h[1] > h[3]) { tmp = h[1]; h[1] = h[3]; h[3] = tmp; }
    if (h[1] > h[2]) { tmp = h[1]; h[1] = h[2]; h[2] = tmp; }
    return ((uint32_t)h[0] << 24) | ((uint32_t)h[1] << 16) | ((uint32_t)h[2] << 8) | (uint32_t)h[3];
}

static size_t sudoku_hash_u32(uint32_t v) {
    uint32_t x = v;
    x ^= x >> 16;
    x *= 0x7feb352dU;
    x ^= x >> 15;
    x *= 0x846ca68bU;
    x ^= x >> 16;
    return (size_t)x;
}

static int sudoku_decode_map_init(sudoku_table_t *table, size_t need_entries) {
    size_t cap = 1;
    while (cap < (need_entries ? need_entries * 2 : 1024)) {
        cap <<= 1;
    }
    table->decode_keys = (uint32_t *)calloc(cap, sizeof(uint32_t));
    table->decode_values = (uint8_t *)calloc(cap, sizeof(uint8_t));
    table->decode_used = (uint8_t *)calloc(cap, sizeof(uint8_t));
    table->decode_cap = cap;
    return table->decode_keys && table->decode_values && table->decode_used ? 0 : -1;
}

static void sudoku_decode_map_put(sudoku_table_t *table, uint32_t key, uint8_t value) {
    size_t mask = table->decode_cap - 1;
    size_t idx = sudoku_hash_u32(key) & mask;
    while (table->decode_used[idx] && table->decode_keys[idx] != key) {
        idx = (idx + 1) & mask;
    }
    table->decode_used[idx] = 1;
    table->decode_keys[idx] = key;
    table->decode_values[idx] = value;
}

static int sudoku_decode_map_get(const sudoku_table_t *table, uint32_t key, uint8_t *value) {
    size_t mask = table->decode_cap - 1;
    size_t idx = sudoku_hash_u32(key) & mask;
    while (table->decode_used[idx]) {
        if (table->decode_keys[idx] == key) {
            *value = table->decode_values[idx];
            return 1;
        }
        idx = (idx + 1) & mask;
    }
    return 0;
}

static void sudoku_sha256(const uint8_t *data, size_t len, uint8_t out[32]) {
#if SUDOKU_CORE_USE_OPENSSL
    SHA256(data, len, out);
#else
    CC_SHA256(data, (CC_LONG)len, out);
#endif
}

static int sudoku_sha256_parts(
    const uint8_t *part1, size_t part1_len,
    const uint8_t *part2, size_t part2_len,
    const uint8_t *part3, size_t part3_len,
    const uint8_t *part4, size_t part4_len,
    const uint8_t *part5, size_t part5_len,
    const uint8_t *part6, size_t part6_len,
    const uint8_t *part7, size_t part7_len,
    const uint8_t *part8, size_t part8_len,
    const uint8_t *part9, size_t part9_len,
    uint8_t out[32]
) {
#if SUDOKU_CORE_USE_OPENSSL
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return -1;
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) goto fail;
    if (part1_len && EVP_DigestUpdate(ctx, part1, part1_len) != 1) goto fail;
    if (part2_len && EVP_DigestUpdate(ctx, part2, part2_len) != 1) goto fail;
    if (part3_len && EVP_DigestUpdate(ctx, part3, part3_len) != 1) goto fail;
    if (part4_len && EVP_DigestUpdate(ctx, part4, part4_len) != 1) goto fail;
    if (part5_len && EVP_DigestUpdate(ctx, part5, part5_len) != 1) goto fail;
    if (part6_len && EVP_DigestUpdate(ctx, part6, part6_len) != 1) goto fail;
    if (part7_len && EVP_DigestUpdate(ctx, part7, part7_len) != 1) goto fail;
    if (part8_len && EVP_DigestUpdate(ctx, part8, part8_len) != 1) goto fail;
    if (part9_len && EVP_DigestUpdate(ctx, part9, part9_len) != 1) goto fail;
    if (EVP_DigestFinal_ex(ctx, out, NULL) != 1) goto fail;
    EVP_MD_CTX_free(ctx);
    return 0;
fail:
    EVP_MD_CTX_free(ctx);
    return -1;
#else
    CC_SHA256_CTX ctx;
    CC_SHA256_Init(&ctx);
    if (part1_len) CC_SHA256_Update(&ctx, part1, (CC_LONG)part1_len);
    if (part2_len) CC_SHA256_Update(&ctx, part2, (CC_LONG)part2_len);
    if (part3_len) CC_SHA256_Update(&ctx, part3, (CC_LONG)part3_len);
    if (part4_len) CC_SHA256_Update(&ctx, part4, (CC_LONG)part4_len);
    if (part5_len) CC_SHA256_Update(&ctx, part5, (CC_LONG)part5_len);
    if (part6_len) CC_SHA256_Update(&ctx, part6, (CC_LONG)part6_len);
    if (part7_len) CC_SHA256_Update(&ctx, part7, (CC_LONG)part7_len);
    if (part8_len) CC_SHA256_Update(&ctx, part8, (CC_LONG)part8_len);
    if (part9_len) CC_SHA256_Update(&ctx, part9, (CC_LONG)part9_len);
    CC_SHA256_Final(out, &ctx);
    return 0;
#endif
}

static uint32_t sudoku_table_hint_fingerprint(
    const char *key,
    const char *mode,
    const char *uplink_pattern,
    const char *downlink_pattern
) {
    uint8_t sum[32];
    uint32_t out;
    static const uint8_t zero_sep = 0;
    if (sudoku_sha256_parts(
            (const uint8_t *)"sudoku-table-hint", 17,
            &zero_sep, 1,
            (const uint8_t *)key, strlen(key),
            &zero_sep, 1,
            (const uint8_t *)mode, strlen(mode),
            &zero_sep, 1,
            (const uint8_t *)uplink_pattern, strlen(uplink_pattern),
            &zero_sep, 1,
            (const uint8_t *)downlink_pattern, strlen(downlink_pattern),
            sum) != 0) {
        memset(sum, 0, sizeof(sum));
    }
    out = ((uint32_t)sum[0] << 24) | ((uint32_t)sum[1] << 16) | ((uint32_t)sum[2] << 8) | (uint32_t)sum[3];
    return out;
}

static void sudoku_layout_ascii(sudoku_layout_t *layout) {
    int i, val, pos, group;
    memset(layout, 0, sizeof(*layout));
    strcpy(layout->name, "ascii");
    layout->pad_marker = 0x3f;
    for (i = 0; i < 32; ++i) {
        layout->padding_pool[layout->padding_pool_len++] = (uint8_t)(0x20 + i);
    }
    for (val = 0; val < 4; ++val) {
        for (pos = 0; pos < 16; ++pos) {
            uint8_t b = (uint8_t)(0x40 | (val << 4) | pos);
            if (b == 0x7f) b = '\n';
            layout->encode_hint[val][pos] = b;
        }
    }
    for (group = 0; group < 64; ++group) {
        uint8_t b = (uint8_t)(0x40 | group);
        if (b == 0x7f) b = '\n';
        layout->encode_group[group] = b;
    }
    for (i = 0; i < 256; ++i) {
        uint8_t b = (uint8_t)i;
        if ((b & 0x40) == 0x40) {
            layout->hint_table[b] = 1;
            layout->decode_group[b] = b & 0x3f;
            layout->group_valid[b] = 1;
        }
    }
    layout->hint_table[(uint8_t)'\n'] = 1;
    layout->decode_group[(uint8_t)'\n'] = 0x3f;
    layout->group_valid[(uint8_t)'\n'] = 1;
}

static void sudoku_layout_entropy(sudoku_layout_t *layout) {
    int i, val, pos, group;
    memset(layout, 0, sizeof(*layout));
    strcpy(layout->name, "entropy");
    layout->pad_marker = 0x80;
    for (i = 0; i < 8; ++i) {
        layout->padding_pool[layout->padding_pool_len++] = (uint8_t)(0x80 + i);
        layout->padding_pool[layout->padding_pool_len++] = (uint8_t)(0x10 + i);
    }
    for (val = 0; val < 4; ++val) {
        for (pos = 0; pos < 16; ++pos) {
            layout->encode_hint[val][pos] = (uint8_t)((val << 5) | pos);
        }
    }
    for (group = 0; group < 64; ++group) {
        uint8_t v = (uint8_t)group;
        layout->encode_group[group] = (uint8_t)(((v & 0x30) << 1) | (v & 0x0f));
    }
    for (i = 0; i < 256; ++i) {
        uint8_t b = (uint8_t)i;
        if ((b & 0x90) != 0) {
            continue;
        }
        layout->hint_table[b] = 1;
        layout->decode_group[b] = (uint8_t)(((b >> 1) & 0x30) | (b & 0x0f));
        layout->group_valid[b] = 1;
    }
}

static int sudoku_layout_custom(sudoku_layout_t *layout, const char *pattern) {
    char cleaned[9];
    uint8_t xbits[2], pbits[2], vbits[4];
    int xcount = 0, pcount = 0, vcount = 0;
    int i, val, pos, group;
    size_t len = 0;
    memset(layout, 0, sizeof(*layout));
    for (; *pattern; ++pattern) {
        if (*pattern == ' ') continue;
        if (len >= 8) return -1;
        cleaned[len++] = (char)tolower((unsigned char)*pattern);
    }
    cleaned[len] = '\0';
    if (len != 8) return -1;
    for (i = 0; i < 8; ++i) {
        uint8_t bit = (uint8_t)(7 - i);
        switch (cleaned[i]) {
            case 'x': if (xcount >= 2) return -1; xbits[xcount++] = bit; break;
            case 'p': if (pcount >= 2) return -1; pbits[pcount++] = bit; break;
            case 'v': if (vcount >= 4) return -1; vbits[vcount++] = bit; break;
            default: return -1;
        }
    }
    if (xcount != 2 || pcount != 2 || vcount != 4) return -1;
    snprintf(layout->name, sizeof(layout->name), "custom(%s)", cleaned);

    for (val = 0; val < 4; ++val) {
        for (pos = 0; pos < 16; ++pos) {
            for (i = 0; i < 2; ++i) {
                uint8_t out = 0;
                out |= (uint8_t)((1u << xbits[0]) | (1u << xbits[1]));
                out &= (uint8_t)~(1u << xbits[i]);
                if (val & 0x02) out |= (uint8_t)(1u << pbits[0]);
                if (val & 0x01) out |= (uint8_t)(1u << pbits[1]);
                for (group = 0; group < 4; ++group) {
                    if ((pos >> (3 - group)) & 1) out |= (uint8_t)(1u << vbits[group]);
                }
                if (__builtin_popcount((unsigned)out) >= 5 && layout->padding_pool_len < sizeof(layout->padding_pool)) {
                    size_t j;
                    int exists = 0;
                    for (j = 0; j < layout->padding_pool_len; ++j) {
                        if (layout->padding_pool[j] == out) {
                            exists = 1;
                            break;
                        }
                    }
                    if (!exists) {
                        layout->padding_pool[layout->padding_pool_len++] = out;
                    }
                }
            }
        }
    }
    if (!layout->padding_pool_len) return -1;
    for (i = 0; i + 1 < (int)layout->padding_pool_len; ++i) {
        int j;
        for (j = i + 1; j < (int)layout->padding_pool_len; ++j) {
            if (layout->padding_pool[j] < layout->padding_pool[i]) {
                uint8_t tmp = layout->padding_pool[i];
                layout->padding_pool[i] = layout->padding_pool[j];
                layout->padding_pool[j] = tmp;
            }
        }
    }
    layout->pad_marker = layout->padding_pool[0];

    for (i = 0; i < 256; ++i) {
        uint8_t wire = (uint8_t)i;
        uint8_t val_out = 0;
        uint8_t pos_out = 0;
        if ((wire & ((1u << xbits[0]) | (1u << xbits[1]))) != ((1u << xbits[0]) | (1u << xbits[1]))) {
            continue;
        }
        layout->hint_table[wire] = 1;
        if (wire & (1u << pbits[0])) val_out |= 0x02;
        if (wire & (1u << pbits[1])) val_out |= 0x01;
        for (group = 0; group < 4; ++group) {
            if (wire & (1u << vbits[group])) {
                pos_out |= (uint8_t)(1u << (3 - group));
            }
        }
        layout->decode_group[wire] = (uint8_t)((val_out << 4) | pos_out);
        layout->group_valid[wire] = 1;
    }
    for (val = 0; val < 4; ++val) {
        for (pos = 0; pos < 16; ++pos) {
            uint8_t out = 0;
            out |= (uint8_t)((1u << xbits[0]) | (1u << xbits[1]));
            if (val & 0x02) out |= (uint8_t)(1u << pbits[0]);
            if (val & 0x01) out |= (uint8_t)(1u << pbits[1]);
            for (group = 0; group < 4; ++group) {
                if ((pos >> (3 - group)) & 1) out |= (uint8_t)(1u << vbits[group]);
            }
            layout->encode_hint[val][pos] = out;
        }
    }
    for (group = 0; group < 64; ++group) {
        layout->encode_group[group] = layout->encode_hint[(group >> 4) & 0x03][group & 0x0f];
    }
    return 0;
}

int sudoku_parse_ascii_mode(const char *mode, sudoku_ascii_mode_t *out_mode) {
    char lower[64];
    size_t len = 0;
    const char *sep;
    if (!mode || !*mode) mode = "prefer_entropy";
    for (; *mode && len + 1 < sizeof(lower); ++mode) {
        lower[len++] = (char)tolower((unsigned char)*mode);
    }
    lower[len] = '\0';
    if (!strcmp(lower, "entropy") || !strcmp(lower, "prefer_entropy") || !strcmp(lower, "")) {
        out_mode->uplink_token = "entropy";
        out_mode->downlink_token = "entropy";
        return 0;
    }
    if (!strcmp(lower, "ascii") || !strcmp(lower, "prefer_ascii")) {
        out_mode->uplink_token = "ascii";
        out_mode->downlink_token = "ascii";
        return 0;
    }
    if (strncmp(lower, "up_", 3)) {
        return -1;
    }
    sep = strstr(lower + 3, "_down_");
    if (!sep) {
        return -1;
    }
    if (!strncmp(lower + 3, "ascii", sep - (lower + 3))) out_mode->uplink_token = "ascii";
    else if (!strncmp(lower + 3, "entropy", sep - (lower + 3))) out_mode->uplink_token = "entropy";
    else return -1;
    if (!strcmp(sep + 6, "ascii")) out_mode->downlink_token = "ascii";
    else if (!strcmp(sep + 6, "entropy")) out_mode->downlink_token = "entropy";
    else return -1;
    return 0;
}

static int sudoku_layout_from_token(sudoku_layout_t *layout, const char *token, const char *custom_pattern) {
    if (!strcmp(token, "ascii")) {
        sudoku_layout_ascii(layout);
        return 0;
    }
    if (custom_pattern && *custom_pattern) {
        return sudoku_layout_custom(layout, custom_pattern);
    }
    sudoku_layout_entropy(layout);
    return 0;
}

static int sudoku_has_unique_match(const sudoku_grid_t *grids, uint8_t pos4[4], uint8_t val4[4]) {
    int count = 0;
    size_t gi;
    for (gi = 0; gi < SUDOKU_GRID_COUNT; ++gi) {
        if (grids[gi].cells[pos4[0]] != val4[0]) continue;
        if (grids[gi].cells[pos4[1]] != val4[1]) continue;
        if (grids[gi].cells[pos4[2]] != val4[2]) continue;
        if (grids[gi].cells[pos4[3]] != val4[3]) continue;
        count++;
        if (count > 1) return 0;
    }
    return count == 1;
}

static int sudoku_table_init_one(sudoku_table_t *table, const char *key, const char *token, const char *custom_pattern) {
    uint8_t sum[32];
    sudoku_grid_t shuffled[SUDOKU_GRID_COUNT];
    size_t gi, hi;
    int byte_val;
    size_t total_entries = 0;
    memset(table, 0, sizeof(*table));
    pthread_once(&sudoku_tables_once, sudoku_build_static_tables);
    if (sudoku_layout_from_token(&table->layout, token, custom_pattern ? custom_pattern : "") != 0) {
        return -1;
    }
    table->is_ascii = (uint8_t)(!strcmp(table->layout.name, "ascii"));
    sudoku_sha256((const uint8_t *)key, strlen(key), sum);
    {
        int64_t seed =
            ((int64_t)sum[0] << 56) | ((int64_t)sum[1] << 48) | ((int64_t)sum[2] << 40) | ((int64_t)sum[3] << 32) |
            ((int64_t)sum[4] << 24) | ((int64_t)sum[5] << 16) | ((int64_t)sum[6] << 8) | (int64_t)sum[7];
        memcpy(shuffled, sudoku_all_grids, sizeof(shuffled));
        sudoku_go_shuffle_grids(shuffled, SUDOKU_GRID_COUNT, seed);
    }
    for (byte_val = 0; byte_val < 256; ++byte_val) {
        const sudoku_grid_t *target = &shuffled[byte_val];
        size_t count = 0;
        for (hi = 0; hi < SUDOKU_HINT_POSITION_COUNT; ++hi) {
            uint8_t pos4[4] = {
                sudoku_hint_positions[hi][0], sudoku_hint_positions[hi][1],
                sudoku_hint_positions[hi][2], sudoku_hint_positions[hi][3]
            };
            uint8_t val4[4] = {
                target->cells[pos4[0]], target->cells[pos4[1]],
                target->cells[pos4[2]], target->cells[pos4[3]]
            };
            if (!sudoku_has_unique_match(sudoku_all_grids, pos4, val4)) {
                continue;
            }
            count++;
        }
        table->encode_table[byte_val] = (sudoku_hint4_t *)calloc(count ? count : 1, sizeof(sudoku_hint4_t));
        table->encode_count[byte_val] = (uint16_t)count;
        total_entries += count;
    }
    if (sudoku_decode_map_init(table, total_entries) != 0) {
        return -1;
    }
    for (byte_val = 0; byte_val < 256; ++byte_val) {
        const sudoku_grid_t *target = &shuffled[byte_val];
        size_t count = 0;
        for (hi = 0; hi < SUDOKU_HINT_POSITION_COUNT; ++hi) {
            uint8_t pos4[4] = {
                sudoku_hint_positions[hi][0], sudoku_hint_positions[hi][1],
                sudoku_hint_positions[hi][2], sudoku_hint_positions[hi][3]
            };
            uint8_t val4[4] = {
                target->cells[pos4[0]], target->cells[pos4[1]],
                target->cells[pos4[2]], target->cells[pos4[3]]
            };
            uint32_t packed;
            if (!sudoku_has_unique_match(sudoku_all_grids, pos4, val4)) {
                continue;
            }
            table->encode_table[byte_val][count].hints[0] = table->layout.encode_hint[val4[0] - 1][pos4[0]];
            table->encode_table[byte_val][count].hints[1] = table->layout.encode_hint[val4[1] - 1][pos4[1]];
            table->encode_table[byte_val][count].hints[2] = table->layout.encode_hint[val4[2] - 1][pos4[2]];
            table->encode_table[byte_val][count].hints[3] = table->layout.encode_hint[val4[3] - 1][pos4[3]];
            packed = sudoku_pack_hints(
                table->encode_table[byte_val][count].hints[0],
                table->encode_table[byte_val][count].hints[1],
                table->encode_table[byte_val][count].hints[2],
                table->encode_table[byte_val][count].hints[3]
            );
            sudoku_decode_map_put(table, packed, (uint8_t)byte_val);
            count++;
        }
        (void)gi;
    }
    return 0;
}

static void sudoku_table_free_one(sudoku_table_t *table) {
    int i;
    for (i = 0; i < 256; ++i) {
        free(table->encode_table[i]);
        table->encode_table[i] = NULL;
    }
    free(table->decode_keys);
    free(table->decode_values);
    free(table->decode_used);
    table->decode_keys = NULL;
    table->decode_values = NULL;
    table->decode_used = NULL;
    table->decode_cap = 0;
}

int sudoku_table_pair_init(
    sudoku_table_pair_t *pair,
    const char *key,
    const char *ascii_mode,
    const char *custom_uplink,
    const char *custom_downlink
) {
    sudoku_ascii_mode_t mode;
    const char *canonical;
    if (sudoku_parse_ascii_mode(ascii_mode, &mode) != 0) {
        return -1;
    }
    memset(pair, 0, sizeof(*pair));
    if (sudoku_table_init_one(&pair->uplink, key, mode.uplink_token, custom_uplink) != 0) {
        sudoku_table_pair_free(pair);
        return -1;
    }
    if (!strcmp(mode.uplink_token, mode.downlink_token) &&
        ((custom_uplink == NULL && custom_downlink == NULL) ||
         ((custom_uplink ? custom_uplink : "")[0] == '\0' && (custom_downlink ? custom_downlink : "")[0] == '\0') ||
         !strcmp(custom_uplink ? custom_uplink : "", custom_downlink ? custom_downlink : ""))) {
        pair->same_direction = 1;
        memcpy(&pair->downlink, &pair->uplink, sizeof(pair->uplink));
    } else {
        if (sudoku_table_init_one(&pair->downlink, key, mode.downlink_token, custom_downlink) != 0) {
            sudoku_table_pair_free(pair);
            return -1;
        }
    }
    canonical =
        (!strcmp(mode.uplink_token, "ascii") && !strcmp(mode.downlink_token, "ascii")) ? "prefer_ascii" :
        ((!strcmp(mode.uplink_token, "entropy") && !strcmp(mode.downlink_token, "entropy")) ? "prefer_entropy" : ascii_mode);
    pair->uplink.hint = sudoku_table_hint_fingerprint(
        key, canonical, custom_uplink ? custom_uplink : "", custom_downlink ? custom_downlink : ""
    );
    pair->downlink.hint = pair->uplink.hint;
    return 0;
}

void sudoku_table_pair_free(sudoku_table_pair_t *pair) {
    if (!pair) return;
    sudoku_table_free_one(&pair->uplink);
    if (!pair->same_direction) {
        sudoku_table_free_one(&pair->downlink);
    }
    memset(pair, 0, sizeof(*pair));
}

size_t sudoku_encode_pure(
    uint8_t *dst,
    size_t dst_cap,
    const sudoku_table_t *table,
    sudoku_splitmix64_t *rng,
    uint64_t padding_threshold,
    const uint8_t *src,
    size_t src_len
) {
    size_t out = 0;
    size_t i;
    for (i = 0; i < src_len; ++i) {
        const sudoku_hint4_t *puzzle;
        const uint8_t *perm;
        int j;
        if (sudoku_should_pad(rng, padding_threshold) && out < dst_cap) {
            dst[out++] = table->layout.padding_pool[sudoku_splitmix64_intn(rng, (int)table->layout.padding_pool_len)];
        }
        puzzle = &table->encode_table[src[i]][sudoku_splitmix64_intn(rng, table->encode_count[src[i]])];
        perm = sudoku_perm4[sudoku_splitmix64_intn(rng, 24)];
        for (j = 0; j < 4; ++j) {
            if (sudoku_should_pad(rng, padding_threshold) && out < dst_cap) {
                dst[out++] = table->layout.padding_pool[sudoku_splitmix64_intn(rng, (int)table->layout.padding_pool_len)];
            }
            if (out < dst_cap) {
                dst[out++] = puzzle->hints[perm[j]];
            }
        }
    }
    if (sudoku_should_pad(rng, padding_threshold) && out < dst_cap) {
        dst[out++] = table->layout.padding_pool[sudoku_splitmix64_intn(rng, (int)table->layout.padding_pool_len)];
    }
    return out;
}

void sudoku_decoder_init(sudoku_decoder_t *decoder) {
    memset(decoder, 0, sizeof(*decoder));
}

static size_t sudoku_drain_pending(uint8_t *dst, size_t dst_cap, uint8_t *pending, size_t *pending_len, size_t *pending_off) {
    size_t available = (*pending_len > *pending_off) ? (*pending_len - *pending_off) : 0;
    size_t n = available < dst_cap ? available : dst_cap;
    if (!n) return 0;
    memcpy(dst, pending + *pending_off, n);
    *pending_off += n;
    if (*pending_off == *pending_len) {
        *pending_off = 0;
        *pending_len = 0;
    }
    return n;
}

size_t sudoku_decode_pure(
    sudoku_decoder_t *decoder,
    const sudoku_table_t *table,
    const uint8_t *src,
    size_t src_len,
    uint8_t *dst,
    size_t dst_cap,
    int *err
) {
    size_t out = 0;
    size_t i;
    uint8_t value = 0;
    if (err) *err = 0;
    out += sudoku_drain_pending(dst, dst_cap, decoder->pending, &decoder->pending_len, &decoder->pending_off);
    if (out == dst_cap) return out;
    for (i = 0; i < src_len; ++i) {
        uint8_t b = src[i];
        uint32_t key;
        if (!table->layout.hint_table[b]) {
            continue;
        }
        decoder->hint_buf[decoder->hint_count++] = b;
        if (decoder->hint_count != 4) {
            continue;
        }
        key = sudoku_pack_hints(
            decoder->hint_buf[0], decoder->hint_buf[1], decoder->hint_buf[2], decoder->hint_buf[3]
        );
        decoder->hint_count = 0;
        if (!sudoku_decode_map_get(table, key, &value)) {
            if (err) *err = -1;
            break;
        }
        if (out < dst_cap) {
            dst[out++] = value;
        } else if (decoder->pending_len < sizeof(decoder->pending)) {
            decoder->pending[decoder->pending_len++] = value;
        }
    }
    return out;
}

void sudoku_packed_decoder_init(sudoku_packed_decoder_t *decoder, const sudoku_table_t *table) {
    memset(decoder, 0, sizeof(*decoder));
    decoder->pad_marker = table->layout.pad_marker;
}

size_t sudoku_decode_packed(
    sudoku_packed_decoder_t *decoder,
    const sudoku_table_t *table,
    const uint8_t *src,
    size_t src_len,
    uint8_t *dst,
    size_t dst_cap,
    int *err
) {
    size_t out = 0;
    size_t i;
    if (err) *err = 0;
    out += sudoku_drain_pending(dst, dst_cap, decoder->pending, &decoder->pending_len, &decoder->pending_off);
    if (out == dst_cap) return out;
    for (i = 0; i < src_len; ++i) {
        uint8_t b = src[i];
        uint8_t group;
        if (!table->layout.hint_table[b]) {
            if (b == decoder->pad_marker) {
                decoder->bitbuf = 0;
                decoder->bitcount = 0;
            }
            continue;
        }
        if (!table->layout.group_valid[b]) {
            if (err) *err = -1;
            break;
        }
        group = table->layout.decode_group[b];
        decoder->bitbuf = (decoder->bitbuf << 6) | group;
        decoder->bitcount += 6;
        while (decoder->bitcount >= 8) {
            uint8_t v;
            decoder->bitcount -= 8;
            v = (uint8_t)(decoder->bitbuf >> decoder->bitcount);
            if (decoder->bitcount == 0) decoder->bitbuf = 0;
            else decoder->bitbuf &= (((uint64_t)1 << decoder->bitcount) - 1);
            if (out < dst_cap) {
                dst[out++] = v;
            } else if (decoder->pending_len < sizeof(decoder->pending)) {
                decoder->pending[decoder->pending_len++] = v;
            }
        }
    }
    return out;
}
