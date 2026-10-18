//
//  SudokuNativeCore.swift
//  Anywhere
//
//  Created by saba-futai on 4/23/26.
//

import Foundation
import CryptoKit

private nonisolated let sudokuProbabilityOne: UInt64 = 1 << 32
/// `hintIdx` values outside `0..<64`. The poison index selects an empty bitset, so a
/// stream carrying such a byte never decodes.
private nonisolated let sudokuPoisonHint: UInt8 = 64
private nonisolated let sudokuNotHint: UInt8 = 0x80
private nonisolated let sudokuObfsDefaultReadChunkSize = 128 * 1024
private nonisolated let sudokuObfsMinDecodeReadSize = 64

nonisolated func sudokuObfsWireReadSize(decodedRemaining: Int, pureDownlink: Bool, maxRaw: Int = sudokuObfsDefaultReadChunkSize) -> Int {
    guard maxRaw > sudokuObfsMinDecodeReadSize, decodedRemaining > 0 else { return maxRaw }
    let multiplier = pureDownlink ? 5 : 2
    if decodedRemaining > (maxRaw - sudokuObfsMinDecodeReadSize) / multiplier {
        return maxRaw
    }
    return min(maxRaw, decodedRemaining * multiplier + sudokuObfsMinDecodeReadSize)
}

/// wyrand. The state advances by a constant, so successive draws do not depend
/// on each other's results and the encoder can overlap them.
nonisolated struct SudokuRandom {
    fileprivate(set) var state: UInt64

    init(seed: Int64) { state = UInt64(bitPattern: seed) }

    mutating func next() -> UInt64 { sudokuWyNext(&state) }

    mutating func pickPaddingThreshold(min pmin: Int32, max pmax: Int32) -> UInt64 {
        var lo = max(Int(pmin), 0)
        var hi = max(Int(pmax), lo)
        lo = min(lo, 100)
        hi = min(hi, 100)
        let minThreshold = (UInt64(lo) * sudokuProbabilityOne) / 100
        let maxThreshold = (UInt64(hi) * sudokuProbabilityOne) / 100
        guard maxThreshold > minThreshold else { return minThreshold }
        return minThreshold + (((next() >> 32) * (maxThreshold - minThreshold)) >> 32)
    }
}

@inline(__always)
private nonisolated func sudokuWyNext(_ state: inout UInt64) -> UInt64 {
    state &+= 0xa0761d6478bd642f
    let product = state.multipliedFullWidth(by: state ^ 0xe7037ed1a0b428db)
    return product.high ^ product.low
}

/// `sudokuPermShifts[4 * i + j]` is the bit offset, inside a packed puzzle, of the
/// hint that the i-th hint order places in slot j.
private nonisolated let sudokuPermShifts: [UInt8] = {
    var shifts = [UInt8]()
    for a in 0..<4 { for b in 0..<4 { for c in 0..<4 { for d in 0..<4 where Set([a, b, c, d]).count == 4 {
        shifts += [UInt8(8 * a), UInt8(8 * b), UInt8(8 * c), UInt8(8 * d)]
    } } } }
    return shifts
}()

private nonisolated let sudokuGoCooked: [Int64] = [
        -4181792142133755926, -4576982950128230565, 1395769623340756751, 5333664234075297259,
        -6347679516498800754, 9033628115061424579, 7143218595135194537, 4812947590706362721,
        7937252194349799378, 5307299880338848416, 8209348851763925077, -7107630437535961764,
        4593015457530856296, 8140875735541888011, -5903942795589686782, -603556388664454774,
        -7496297993371156308, 113108499721038619, 4569519971459345583, -4160538177779461077,
        -6835753265595711384, -6507240692498089696, 6559392774825876886, 7650093201692370310,
        7684323884043752161, -8965504200858744418, -2629915517445760644, 271327514973697897,
        -6433985589514657524, 1065192797246149621, 3344507881999356393, -4763574095074709175,
        7465081662728599889, 1014950805555097187, -4773931307508785033, -5742262670416273165,
        2418672789110888383, 5796562887576294778, 4484266064449540171, 3738982361971787048,
        -4699774852342421385, 10530508058128498, -589538253572429690, -6598062107225984180,
        8660405965245884302, 10162832508971942, -2682657355892958417, 7031802312784620857,
        6240911277345944669, 831864355460801054, -1218937899312622917, 2116287251661052151,
        2202309800992166967, 9161020366945053561, 4069299552407763864, 4936383537992622449,
        457351505131524928, -8881176990926596454, -6375600354038175299, -7155351920868399290,
        4368649989588021065, 887231587095185257, -3659780529968199312, -2407146836602825512,
        5616972787034086048, -751562733459939242, 1686575021641186857, -5177887698780513806,
        -4979215821652996885, -1375154703071198421, 5632136521049761902, -8390088894796940536,
        -193645528485698615, -5979788902190688516, -4907000935050298721, -285522056888777828,
        -2776431630044341707, 1679342092332374735, 6050638460742422078, -2229851317345194226,
        -1582494184340482199, 5881353426285907985, 812786550756860885, 4541845584483343330,
        -6497901820577766722, 4980675660146853729, -4012602956251539747, -329088717864244987,
        -2896929232104691526, 1495812843684243920, -2153620458055647789, 7370257291860230865,
        -2466442761497833547, 4706794511633873654, -1398851569026877145, 8549875090542453214,
        -9189721207376179652, -7894453601103453165, 7297902601803624459, 1011190183918857495,
        -6985347000036920864, 5147159997473910359, -8326859945294252826, 2659470849286379941,
        6097729358393448602, -7491646050550022124, -5117116194870963097, -896216826133240300,
        -745860416168701406, 5803876044675762232, -787954255994554146, -3234519180203704564,
        -4507534739750823898, -1657200065590290694, 505808562678895611, -4153273856159712438,
        -8381261370078904295, 572156825025677802, 1791881013492340891, 3393267094866038768,
        -5444650186382539299, 2352769483186201278, -7930912453007408350, -325464993179687389,
        -3441562999710612272, -6489413242825283295, 5092019688680754699, -227247482082248967,
        4234737173186232084, 5027558287275472836, 4635198586344772304, -536033143587636457,
        5907508150730407386, -8438615781380831356, 972392927514829904, -3801314342046600696,
        -4064951393885491917, -174840358296132583, 2407211146698877100, -1640089820333676239,
        3940796514530962282, -5882197405809569433, 3095313889586102949, -1818050141166537098,
        5832080132947175283, 7890064875145919662, 8184139210799583195, -8073512175445549678,
        -7758774793014564506, -4581724029666783935, 3516491885471466898, -8267083515063118116,
        6657089965014657519, 5220884358887979358, 1796677326474620641, 5340761970648932916,
        1147977171614181568, 5066037465548252321, 2574765911837859848, 1085848279845204775,
        -5873264506986385449, 6116438694366558490, 2107701075971293812, -7420077970933506541,
        2469478054175558874, -1855128755834809824, -5431463669011098282, -9038325065738319171,
        -6966276280341336160, 7217693971077460129, -8314322083775271549, 7196649268545224266,
        -3585711691453906209, -5267827091426810625, 8057528650917418961, -5084103596553648165,
        -2601445448341207749, -7850010900052094367, 6527366231383600011, 3507654575162700890,
        9202058512774729859, 1954818376891585542, -2582991129724600103, 8299563319178235687,
        -5321504681635821435, 7046310742295574065, -2376176645520785576, -7650733936335907755,
        8850422670118399721, 3631909142291992901, 5158881091950831288, -6340413719511654215,
        4763258931815816403, 6280052734341785344, -4979582628649810958, 2043464728020827976,
        -2678071570832690343, 4562580375758598164, 5495451168795427352, -7485059175264624713,
        553004618757816492, 6895160632757959823, -989748114590090637, 7139506338801360852,
        -672480814466784139, 5535668688139305547, 2430933853350256242, -3821430778991574732,
        -1063731997747047009, -3065878205254005442, 7632066283658143750, 6308328381617103346,
        3681878764086140361, 3289686137190109749, 6587997200611086848, 244714774258135476,
        -5143583659437639708, 8090302575944624335, 2945117363431356361, -8359047641006034763,
        3009039260312620700, -793344576772241777, 401084700045993341, -1968749590416080887,
        4707864159563588614, -3583123505891281857, -3240864324164777915, -5908273794572565703,
        -3719524458082857382, -5281400669679581926, 8118566580304798074, 3839261274019871296,
        7062410411742090847, -8481991033874568140, 6027994129690250817, -6725542042704711878,
        -2971981702428546974, -7854441788951256975, 8809096399316380241, 6492004350391900708,
        2462145737463489636, -8818543617934476634, -5070345602623085213, -8961586321599299868,
        -3758656652254704451, -8630661632476012791, 6764129236657751224, -709716318315418359,
        -3403028373052861600, -8838073512170985897, -3999237033416576341, -2920240395515973663,
        -2073249475545404416, 368107899140673753, -6108185202296464250, -6307735683270494757,
        4782583894627718279, 6718292300699989587, 8387085186914375220, 3387513132024756289,
        4654329375432538231, -292704475491394206, -3848998599978456535, 7623042350483453954,
        7725442901813263321, 9186225467561587250, -5132344747257272453, -6865740430362196008,
        2530936820058611833, 1636551876240043639, -3658707362519810009, 1452244145334316253,
        -7161729655835084979, -7943791770359481772, 9108481583171221009, -3200093350120725999,
        5007630032676973346, 2153168792952589781, 6720334534964750538, -3181825545719981703,
        3433922409283786309, 2285479922797300912, 3110614940896576130, -2856812446131932915,
        -3804580617188639299, 7163298419643543757, 4891138053923696990, 580618510277907015,
        1684034065251686769, 4429514767357295841, -8893025458299325803, -8103734041042601133,
        7177515271653460134, 4589042248470800257, -1530083407795771245, 143607045258444228,
        246994305896273627, -8356954712051676521, 6473547110565816071, 3092379936208876896,
        2058427839513754051, -4089587328327907870, 8785882556301281247, -3074039370013608197,
        -637529855400303673, 6137678347805511274, -7152924852417805802, 5708223427705576541,
        -3223714144396531304, 4358391411789012426, 325123008708389849, 6837621693887290924,
        4843721905315627004, -3212720814705499393, -3825019837890901156, 4602025990114250980,
        1044646352569048800, 9106614159853161675, -8394115921626182539, -4304087667751778808,
        2681532557646850893, 3681559472488511871, -3915372517896561773, -2889241648411946534,
        -6564663803938238204, -8060058171802589521, 581945337509520675, 3648778920718647903,
        -4799698790548231394, -7602572252857820065, 220828013409515943, -1072987336855386047,
        4287360518296753003, -4633371852008891965, 5513660857261085186, -2258542936462001533,
        -8744380348503999773, 8746140185685648781, 228500091334420247, 1356187007457302238,
        3019253992034194581, 3152601605678500003, -8793219284148773595, 5559581553696971176,
        4916432985369275664, -8559797105120221417, -5802598197927043732, 2868348622579915573,
        -7224052902810357288, -5894682518218493085, 2587672709781371173, -7706116723325376475,
        3092343956317362483, -5561119517847711700, 972445599196498113, -1558506600978816441,
        1708913533482282562, -2305554874185907314, -6005743014309462908, -6653329009633068701,
        -483583197311151195, 2488075924621352812, -4529369641467339140, -4663743555056261452,
        2997203966153298104, 1282559373026354493, 240113143146674385, 8665713329246516443,
        628141331766346752, -4651421219668005332, -7750560848702540400, 7596648026010355826,
        -3132152619100351065, 7834161864828164065, 7103445518877254909, 4390861237357459201,
        -4780718172614204074, -319889632007444440, 622261699494173647, -3186110786557562560,
        -8718967088789066690, -1948156510637662747, -8212195255998774408, -7028621931231314745,
        2623071828615234808, -4066058308780939700, -5484966924888173764, -6683604512778046238,
        -6756087640505506466, 5256026990536851868, 7841086888628396109, 6640857538655893162,
        -8021284697816458310, -7109857044414059830, -1689021141511844405, -4298087301956291063,
        -4077748265377282003, -998231156719803476, 2719520354384050532, 9132346697815513771,
        4332154495710163773, -2085582442760428892, 6994721091344268833, -2556143461985726874,
        -8567931991128098309, 59934747298466858, -3098398008776739403, -265597256199410390,
        2332206071942466437, -7522315324568406181, 3154897383618636503, -7585605855467168281,
        -6762850759087199275, 197309393502684135, -8579694182469508493, 2543179307861934850,
        4350769010207485119, -4468719947444108136, -7207776534213261296, -1224312577878317200,
        4287946071480840813, 8362686366770308971, 6486469209321732151, -5605644191012979782,
        -1669018511020473564, 4450022655153542367, -7618176296641240059, -3896357471549267421,
        -4596796223304447488, -6531150016257070659, -8982326463137525940, -4125325062227681798,
        -1306489741394045544, -8338554946557245229, 5329160409530630596, 7790979528857726136,
        4955070238059373407, -4304834761432101506, -6215295852904371179, 3007769226071157901,
        -6753025801236972788, 8928702772696731736, 7856187920214445904, -4748497451462800923,
        7900176660600710914, -7082800908938549136, -6797926979589575837, -6737316883512927978,
        4186670094382025798, 1883939007446035042, -414705992779907823, 3734134241178479257,
        4065968871360089196, 6953124200385847784, -7917685222115876751, -7585632937840318161,
        -5567246375906782599, -5256612402221608788, 3106378204088556331, -2894472214076325998,
        4565385105440252958, 1979884289539493806, -6891578849933910383, 3783206694208922581,
        8464961209802336085, 2843963751609577687, 3030678195484896323, -4429654462759003204,
        4459239494808162889, 402587895800087237, 8057891408711167515, 4541888170938985079,
        1042662272908816815, -3666068979732206850, 2647678726283249984, 2144477441549833761,
        -3417019821499388721, -2105601033380872185, 5916597177708541638, -8760774321402454447,
        8833658097025758785, 5970273481425315300, 563813119381731307, -6455022486202078793,
        1598828206250873866, -4016978389451217698, -2988328551145513985, -6071154634840136312,
        8469693267274066490, 125672920241807416, -3912292412830714870, -2559617104544284221,
        -486523741806024092, -4735332261862713930, 5923302823487327109, -9082480245771672572,
        -1808429243461201518, 7990420780896957397, 4317817392807076702, 3625184369705367340,
        -6482649271566653105, -3480272027152017464, -3225473396345736649, -368878695502291645,
        -3981164001421868007, -8522033136963788610, 7609280429197514109, 3020985755112334161,
        -2572049329799262942, 2635195723621160615, 5144520864246028816, -8188285521126945980,
        1567242097116389047, 8172389260191636581, -2885551685425483535, -7060359469858316883,
        -6480181133964513127, -7317004403633452381, 6011544915663598137, 5932255307352610768,
        2241128460406315459, -8327867140638080220, 3094483003111372717, 4583857460292963101,
        9079887171656594975, -384082854924064405, -3460631649611717935, 4225072055348026230,
        -7385151438465742745, 3801620336801580414, -399845416774701952, -7446754431269675473,
        7899055018877642622, 5421679761463003041, 5521102963086275121, -4975092593295409910,
        8735487530905098534, -7462844945281082830, -2080886987197029914, -1000715163927557685,
        -4253840471931071485, -5828896094657903328, 6424174453260338141, 359248545074932887,
        -5949720754023045210, -2426265837057637212, 3030918217665093212, -9077771202237461772,
        -3186796180789149575, 740416251634527158, -2142944401404840226, 6951781370868335478,
        399922722363687927, -8928469722407522623, -1378421100515597285, -8343051178220066766,
        -3030716356046100229, -8811767350470065420, 9026808440365124461, 6440783557497587732,
        4615674634722404292, 539897290441580544, 2096238225866883852, 8751955639408182687,
        -7316147128802486205, 7381039757301768559, 6157238513393239656, -1473377804940618233,
        8629571604380892756, 5280433031239081479, 7101611890139813254, 2479018537985767835,
        7169176924412769570, -1281305539061572506, -7865612307799218120, 2278447439451174845,
        3625338785743880657, 6477479539006708521, 8976185375579272206, -3712000482142939688,
        1326024180520890843, 7537449876596048829, 5464680203499696154, 3189671183162196045,
        6346751753565857109, -8982212049534145501, -6127578587196093755, -245039190118465649,
        -6320577374581628592, 7208698530190629697, 7276901792339343736, -7490986807540332668,
        4133292154170828382, 2918308698224194548, -7703910638917631350, -3929437324238184044,
        -4300543082831323144, -6344160503358350167, 5896236396443472108, -758328221503023383,
        -1894351639983151068, -307900319840287220, -6278469401177312761, -2171292963361310674,
        8382142935188824023, 9103922860780351547, 4152330101494654406
]

nonisolated private struct SudokuGoSource {
    private var tap = 0
    private var feed = 607 - 273
    private var lagTable = Array(repeating: Int64(0), count: 607)

    init(seed: Int64) { seedSource(seed) }

    private static func seedrand(_ value: Int32) -> Int32 {
        let a: Int32 = 48271
        let q: Int32 = 44488
        let r: Int32 = 3399
        let hi = value / q
        let lo = value % q
        var x = a * lo - r * hi
        if x < 0 { x += 2147483647 }
        return x
    }

    private mutating func seedSource(_ seed: Int64) {
        tap = 0
        feed = 607 - 273
        var s = seed % 2147483647
        if s < 0 { s += 2147483647 }
        if s == 0 { s = 89482311 }
        var x = Int32(s)
        for i in -20..<607 {
            x = Self.seedrand(x)
            if i < 0 { continue }
            var u = Int64(x) << 40
            x = Self.seedrand(x)
            u ^= Int64(x) << 20
            x = Self.seedrand(x)
            u ^= Int64(x)
            u ^= sudokuGoCooked[i]
            lagTable[i] = u
        }
    }

    mutating func uint64() -> UInt64 {
        tap -= 1
        if tap < 0 { tap += 607 }
        feed -= 1
        if feed < 0 { feed += 607 }
        let x = lagTable[feed] &+ lagTable[tap]
        lagTable[feed] = x
        return UInt64(bitPattern: x)
    }

    mutating func int31n(_ n: Int32) -> Int32 {
        var x = uint64() & 0x7fffffffffffffff
        var v = UInt32(truncatingIfNeeded: x >> 31)
        var prod = UInt64(v) * UInt64(UInt32(bitPattern: n))
        var low = UInt32(truncatingIfNeeded: prod)
        if low < UInt32(bitPattern: n) {
            let thresh = UInt32(bitPattern: -n) % UInt32(bitPattern: n)
            while low < thresh {
                x = uint64() & 0x7fffffffffffffff
                v = UInt32(truncatingIfNeeded: x >> 31)
                prod = UInt64(v) * UInt64(UInt32(bitPattern: n))
                low = UInt32(truncatingIfNeeded: prod)
            }
        }
        return Int32(truncatingIfNeeded: prod >> 32)
    }
}

nonisolated private struct SudokuStaticTables {
    let grids: [[UInt8]]
    let hintPositions: [[UInt8]]

    static let shared = SudokuStaticTables()

    private init() {
        var builtGrids = [[UInt8]]()
        var current = Array(repeating: UInt8(0), count: 16)
        Self.generateGrids(current: &current, index: 0, output: &builtGrids)
        var positions = [[UInt8]]()
        for a in 0..<13 {
            for b in (a + 1)..<14 {
                for c in (b + 1)..<15 {
                    for d in (c + 1)..<16 { positions.append([UInt8(a), UInt8(b), UInt8(c), UInt8(d)]) }
                }
            }
        }
        grids = builtGrids
        hintPositions = positions
    }

    private static func valid(_ grid: [UInt8], index: Int, number: UInt8) -> Bool {
        let row = index / 4
        let col = index % 4
        let br = (row / 2) * 2
        let bc = (col / 2) * 2
        for i in 0..<4 {
            if grid[row * 4 + i] == number || grid[i * 4 + col] == number { return false }
        }
        for r in 0..<2 {
            for c in 0..<2 where grid[(br + r) * 4 + (bc + c)] == number { return false }
        }
        return true
    }

    private static func generateGrids(current: inout [UInt8], index: Int, output: inout [[UInt8]]) {
        if index == 16 {
            output.append(current)
            return
        }
        for number in UInt8(1)...UInt8(4) where valid(current, index: index, number: number) {
            current[index] = number
            generateGrids(current: &current, index: index + 1, output: &output)
            current[index] = 0
        }
    }
}

nonisolated private struct SudokuLayout {
    let name: String
    let padMarker: UInt8
    let paddingPool: [UInt8]
    let encodeHint: [[UInt8]]
    /// `pos << 2 | val` of each hint byte, `sudokuPoisonHint` for a hint-class byte no
    /// encoder emits and `sudokuNotHint` for everything else.
    let hintIdx: [UInt8]
    /// Packed groups are 0...63; 0xff marks padding and other non-hint bytes.
    let decodeGroup: [UInt8]

    private static func indexHints(hintClass: [Bool], encodeHint: [[UInt8]]) -> [UInt8] {
        var index = hintClass.map { $0 ? sudokuPoisonHint : sudokuNotHint }
        for value in 0..<4 { for position in 0..<16 { index[Int(encodeHint[value][position])] = UInt8(position << 2 | value) } }
        return index
    }

    static func ascii() -> SudokuLayout {
        var padding = [UInt8](); for i in 0..<32 { padding.append(UInt8(0x20 + i)) }
        var encodeHint = Array(repeating: Array(repeating: UInt8(0), count: 16), count: 4)
        for value in 0..<4 { for position in 0..<16 { var b = UInt8(0x40 | (value << 4) | position); if b == 0x7f { b = 0x0a }; encodeHint[value][position] = b } }
        var hint = Array(repeating: false, count: 256)
        var decode = Array(repeating: UInt8.max, count: 256)
        for i in 0..<256 {
            let b = UInt8(i)
            if (b & 0x40) == 0x40 { hint[i] = true; decode[i] = b & 0x3f }
        }
        hint[0x0a] = true; decode[0x0a] = 0x3f
        return SudokuLayout(name: "ascii", padMarker: 0x3f, paddingPool: padding, encodeHint: encodeHint, hintIdx: indexHints(hintClass: hint, encodeHint: encodeHint), decodeGroup: decode)
    }

    static func entropy() -> SudokuLayout {
        var padding = [UInt8](); for i in 0..<8 { padding.append(UInt8(0x80 + i)); padding.append(UInt8(0x10 + i)) }
        var encodeHint = Array(repeating: Array(repeating: UInt8(0), count: 16), count: 4)
        for value in 0..<4 { for position in 0..<16 { encodeHint[value][position] = UInt8((value << 5) | position) } }
        var hint = Array(repeating: false, count: 256)
        var decode = Array(repeating: UInt8.max, count: 256)
        for i in 0..<256 {
            let b = UInt8(i)
            if (b & 0x90) == 0 { hint[i] = true; decode[i] = ((b >> 1) & 0x30) | (b & 0x0f) }
        }
        return SudokuLayout(name: "entropy", padMarker: 0x80, paddingPool: padding, encodeHint: encodeHint, hintIdx: indexHints(hintClass: hint, encodeHint: encodeHint), decodeGroup: decode)
    }

    static func custom(_ pattern: String) throws -> SudokuLayout {
        let cleaned = pattern.lowercased().filter { $0 != " " }
        guard cleaned.count == 8 else { throw AnywhereError.proxy(.sudoku, .invalidConfiguration(detail: "invalid custom Sudoku table")) }
        var xbits = [UInt8](), pbits = [UInt8](), vbits = [UInt8]()
        for (i, ch) in cleaned.enumerated() {
            let bit = UInt8(7 - i)
            switch ch {
            case "x": guard xbits.count < 2 else { throw AnywhereError.proxy(.sudoku, .invalidConfiguration(detail: "invalid custom Sudoku table")) }; xbits.append(bit)
            case "p": guard pbits.count < 2 else { throw AnywhereError.proxy(.sudoku, .invalidConfiguration(detail: "invalid custom Sudoku table")) }; pbits.append(bit)
            case "v": guard vbits.count < 4 else { throw AnywhereError.proxy(.sudoku, .invalidConfiguration(detail: "invalid custom Sudoku table")) }; vbits.append(bit)
            default: throw AnywhereError.proxy(.sudoku, .invalidConfiguration(detail: "invalid custom Sudoku table"))
            }
        }
        guard xbits.count == 2, pbits.count == 2, vbits.count == 4 else { throw AnywhereError.proxy(.sudoku, .invalidConfiguration(detail: "invalid custom Sudoku table")) }
        var padding = [UInt8](); var encodeHint = Array(repeating: Array(repeating: UInt8(0), count: 16), count: 4)
        for value in 0..<4 { for position in 0..<16 { for i in 0..<2 { var out = UInt8((1 << xbits[0]) | (1 << xbits[1])); out &= ~UInt8(1 << xbits[i]); if (value & 2) != 0 { out |= UInt8(1 << pbits[0]) }; if (value & 1) != 0 { out |= UInt8(1 << pbits[1]) }; for group in 0..<4 where ((position >> (3 - group)) & 1) != 0 { out |= UInt8(1 << vbits[group]) }; if out.nonzeroBitCount >= 5, !padding.contains(out) { padding.append(out) } } } }
        guard !padding.isEmpty else { throw AnywhereError.proxy(.sudoku, .invalidConfiguration(detail: "invalid custom Sudoku table")) }
        padding.sort()
        var hint = Array(repeating: false, count: 256)
        var decode = Array(repeating: UInt8.max, count: 256)
        let xmask = UInt8((1 << xbits[0]) | (1 << xbits[1]))
        for i in 0..<256 {
            let wire = UInt8(i)
            guard (wire & xmask) == xmask else { continue }
            var valOut = UInt8(0), posOut = UInt8(0)
            if (wire & UInt8(1 << pbits[0])) != 0 { valOut |= 0x02 }
            if (wire & UInt8(1 << pbits[1])) != 0 { valOut |= 0x01 }
            for group in 0..<4 where (wire & UInt8(1 << vbits[group])) != 0 { posOut |= UInt8(1 << (3 - group)) }
            hint[i] = true; decode[i] = (valOut << 4) | posOut
        }
        for value in 0..<4 { for position in 0..<16 { var out = xmask; if (value & 2) != 0 { out |= UInt8(1 << pbits[0]) }; if (value & 1) != 0 { out |= UInt8(1 << pbits[1]) }; for group in 0..<4 where ((position >> (3 - group)) & 1) != 0 { out |= UInt8(1 << vbits[group]) }; encodeHint[value][position] = out } }
        return SudokuLayout(name: "custom(\(cleaned))", padMarker: padding[0], paddingPool: padding, encodeHint: encodeHint, hintIdx: indexHints(hintClass: hint, encodeHint: encodeHint), decodeGroup: decode)
    }
}

private nonisolated func sudokuSHA256(_ string: String) -> [UInt8] { Array(SHA256.hash(data: Data(string.utf8))) }
private nonisolated func sudokuSHA256(_ data: Data) -> [UInt8] { Array(SHA256.hash(data: data)) }

/// One direction of the obfuscation: the puzzles each plaintext byte may be written as,
/// and the inverse lookup.
///
/// Every grid of `SudokuStaticTables` gets a rank in the key-shuffled order, and the first
/// 256 ranks are the plaintext bytes. `hintSets[pos << 2 | val]` holds bit `rank` when that
/// grid has `val` at `pos`, so four hints name a byte exactly when their sets share a single
/// grid whose rank is below 256.
nonisolated final class SudokuTable: @unchecked Sendable {
    fileprivate let layout: SudokuLayout
    let hint: UInt32
    /// The immutable tables below live in one allocation, owned by the table, so the codec
    /// loops read them through plain pointers.
    private let storage: UnsafeMutableRawPointer
    /// `puzzles[puzzleStart[b]..<puzzleStart[b + 1]]` are the puzzles of plaintext byte `b`.
    /// A puzzle packs the four hint bytes of its cells, first hint lowest.
    fileprivate let puzzleStart: UnsafePointer<UInt32>
    fileprivate let puzzles: UnsafePointer<UInt32>
    fileprivate let hintSets: UnsafePointer<UInt64>
    fileprivate let hintIdx: UnsafePointer<UInt8>
    fileprivate let decodeGroup: UnsafePointer<UInt8>
    fileprivate let paddingPool: UnsafePointer<UInt8>
    fileprivate let permShifts: UnsafePointer<UInt8>

    init(key: String, token: String, customPattern: String, hint: UInt32) throws {
        self.hint = hint
        let layout: SudokuLayout
        if token == "ascii" { layout = .ascii() }
        else if !customPattern.isEmpty { layout = try .custom(customPattern) }
        else { layout = .entropy() }
        self.layout = layout
        let statics = SudokuStaticTables.shared
        var shuffled = statics.grids
        let sum = sudokuSHA256(key)
        var seed = UInt64(0)
        for b in sum.prefix(8) { seed = (seed << 8) | UInt64(b) }
        var rng = SudokuGoSource(seed: Int64(bitPattern: seed))
        if !shuffled.isEmpty {
            for i in stride(from: shuffled.count - 1, through: 1, by: -1) {
                let j = Int(rng.int31n(Int32(i + 1)))
                shuffled.swapAt(i, j)
            }
        }

        var sets = [UInt64](repeating: 0, count: 128 * 5)
        for (rank, grid) in shuffled.enumerated() {
            for position in 0..<16 {
                sets[((position << 2 | Int(grid[position] - 1)) * 5) + (rank >> 6)] |= 1 << UInt64(rank & 63)
            }
        }
        var puzzleStart = [UInt32](repeating: 0, count: 257)
        var puzzles = [UInt32]()
        puzzles.reserveCapacity(24 << 10)
        sets.withUnsafeBufferPointer { sets in
            for byteValue in 0..<256 {
                puzzleStart[byteValue] = UInt32(puzzles.count)
                let grid = shuffled[byteValue]
                for positions in statics.hintPositions {
                    var hints = [UInt8](repeating: 0, count: 4)
                    for i in 0..<4 { hints[i] = UInt8(Int(positions[i]) << 2 | Int(grid[Int(positions[i])] - 1)) }
                    guard Self.decodeHints(sets.baseAddress!, hints[0], hints[1], hints[2], hints[3]) == byteValue else { continue }
                    var puzzle = UInt32(0)
                    for i in 0..<4 {
                        let position = Int(positions[i])
                        puzzle |= UInt32(layout.encodeHint[Int(grid[position] - 1)][position]) << UInt32(8 * i)
                    }
                    puzzles.append(puzzle)
                }
            }
        }
        puzzleStart[256] = UInt32(puzzles.count)

        let sizes = [puzzleStart.count * 4, puzzles.count * 4, sets.count * 8, 256, 256, layout.paddingPool.count, sudokuPermShifts.count]
        let offsets = sizes.reduce(into: [0]) { $0.append(($0.last! + $1 + 7) & ~7) }
        let base = UnsafeMutableRawPointer.allocate(byteCount: offsets.last!, alignment: 8)
        func place<T>(_ values: [T], _ slot: Int) -> UnsafePointer<T> {
            let destination = (base + offsets[slot]).bindMemory(to: T.self, capacity: values.count)
            destination.initialize(from: values, count: values.count)
            return UnsafePointer(destination)
        }
        storage = base
        self.puzzleStart = place(puzzleStart, 0)
        self.puzzles = place(puzzles, 1)
        hintSets = place(sets, 2)
        hintIdx = place(layout.hintIdx, 3)
        decodeGroup = place(layout.decodeGroup, 4)
        paddingPool = place(layout.paddingPool, 5)
        permShifts = place(sudokuPermShifts, 6)
    }

    deinit { storage.deallocate() }

    /// The plaintext byte whose puzzle is exactly these four hint indexes, or -1.
    @inline(__always)
    fileprivate static func decodeHints(_ sets: UnsafePointer<UInt64>, _ a: UInt8, _ b: UInt8, _ c: UInt8, _ d: UInt8) -> Int {
        let sa = sets + Int(a & 127) * 5
        let sb = sets + Int(b & 127) * 5
        let sc = sets + Int(c & 127) * 5
        let sd = sets + Int(d & 127) * 5
        let r0 = sa[0] & sb[0] & sc[0] & sd[0]
        let r1 = sa[1] & sb[1] & sc[1] & sd[1]
        let r2 = sa[2] & sb[2] & sc[2] & sd[2]
        let r3 = sa[3] & sb[3] & sc[3] & sd[3]
        let r4 = sa[4] & sb[4] & sc[4] & sd[4]
        // Exactly one shared grid, and it must be one of the 256 that carry a byte.
        let multi = (r0 & (r0 &- 1)) | (r1 & (r1 &- 1)) | (r2 & (r2 &- 1)) | (r3 & (r3 &- 1)) | r4
        let nonEmpty = (r0 != 0 ? 1 : 0) + (r1 != 0 ? 1 : 0) + (r2 != 0 ? 1 : 0) + (r3 != 0 ? 1 : 0)
        let word = r3 != 0 ? 192 : (r2 != 0 ? 128 : (r1 != 0 ? 64 : 0))
        let rank = word + (r0 | r1 | r2 | r3).trailingZeroBitCount
        return multi == 0 && nonEmpty == 1 ? rank : -1
    }

    /// Encodes `data` as puzzles: each byte becomes the four hints of one of its puzzles in a
    /// random order, with a padding byte possible before the group and before each hint.
    /// `paddingThreshold` is the per-slot padding probability scaled to 2^32, so 2^32 pads
    /// every slot. A write that pads at all also gets one more slot after its last hint.
    func encode(_ data: Data, rng: inout SudokuRandom, paddingThreshold: UInt64) -> Data {
        // Worst case per byte is five padding slots and four hints. The padded loop stores
        // each byte through a 16-byte window, hence the slack.
        let capacity = data.count * (paddingThreshold == 0 ? 4 : 9) + 16
        var state = rng.state
        let encoded = SudokuBufferPool.makeData(capacity: capacity) { rawOutput in
            let output = rawOutput.baseAddress!.assumingMemoryBound(to: UInt8.self)
            var written = 0
            data.withUnsafeBytes { rawInput in
                let input = rawInput.bindMemory(to: UInt8.self)
                if paddingThreshold == 0 {
                    for byte in input {
                        let puzzle = pickPuzzle(byte, sudokuWyNext(&state))
                        UnsafeMutableRawPointer(output + written).storeBytes(of: puzzle.littleEndian, as: UInt32.self)
                        written += 4
                    }
                    return
                }
                let poolCount = UInt64(layout.paddingPool.count)
                // Writes a candidate padding byte at window[k] and keeps it only when the
                // slot's draw falls under the threshold, so a slot that draws none leaves k
                // alone and the next store overwrites the candidate.
                func padSlot(_ window: UnsafeMutablePointer<UInt8>, _ k: Int) -> Int {
                    let draw = sudokuWyNext(&state)
                    window[k & 15] = paddingPool[Int(((draw >> 32) &* poolCount) >> 32)]
                    return k &+ Int(((draw & 0xffff_ffff) &- paddingThreshold) >> 63)
                }
                for byte in input {
                    let hints = pickPuzzle(byte, sudokuWyNext(&state))
                    let window = output + written
                    var k = padSlot(window, 0)
                    k = padSlot(window, k)
                    window[k & 15] = UInt8(truncatingIfNeeded: hints)
                    k = padSlot(window, k + 1)
                    window[k & 15] = UInt8(truncatingIfNeeded: hints >> 8)
                    k = padSlot(window, k + 1)
                    window[k & 15] = UInt8(truncatingIfNeeded: hints >> 16)
                    k = padSlot(window, k + 1)
                    window[k & 15] = UInt8(truncatingIfNeeded: hints >> 24)
                    written += k + 1
                }
                let draw = sudokuWyNext(&state)
                if draw & 0xffff_ffff < paddingThreshold {
                    output[written] = paddingPool[Int(((draw >> 32) &* poolCount) >> 32)]
                    written += 1
                }
            }
            return written
        }
        rng.state = state
        return encoded
    }

    /// One draw picks a puzzle of byte `b` and the order its hints are written in.
    @inline(__always)
    private func pickPuzzle(_ b: UInt8, _ draw: UInt64) -> UInt32 {
        let first = Int(puzzleStart[Int(b)])
        let count = UInt64(puzzleStart[Int(b) + 1]) &- UInt64(first)
        let puzzle = puzzles[first + Int(((draw >> 32) &* count) >> 32)]
        let s = permShifts + Int(((draw & 0xffff_ffff) &* 24) >> 32) * 4
        return (puzzle &>> UInt32(s[0]) & 0xff)
            | (puzzle &>> UInt32(s[1]) & 0xff) << 8
            | (puzzle &>> UInt32(s[2]) & 0xff) << 16
            | (puzzle &>> UInt32(s[3])) << 24
    }
}

nonisolated final class SudokuTablePair: Sendable {
    let uplink: SudokuTable
    let downlink: SudokuTable

    init(key: String, asciiMode: String, customUplink: String, customDownlink: String) throws {
        let mode = try Self.parseMode(asciiMode)
        let uplinkPattern = mode.uplink == "entropy" ? customUplink : ""
        let downlinkPattern = mode.downlink == "entropy" ? customDownlink : ""
        let canonical = mode.uplink == "ascii" && mode.downlink == "ascii" ? "prefer_ascii" : (mode.uplink == "entropy" && mode.downlink == "entropy" ? "prefer_entropy" : asciiMode)
        let hint = Self.tableHintFingerprint(key: key, mode: canonical, uplinkPattern: uplinkPattern, downlinkPattern: downlinkPattern)
        uplink = try SudokuTable(key: key, token: mode.uplink, customPattern: uplinkPattern, hint: hint)
        if mode.uplink == mode.downlink && uplinkPattern == downlinkPattern {
            downlink = uplink
        } else {
            downlink = try SudokuTable(key: key, token: mode.downlink, customPattern: downlinkPattern, hint: hint)
        }
    }

    private static func parseMode(_ raw: String) throws -> (uplink: String, downlink: String) {
        let lower = raw.isEmpty ? "prefer_entropy" : raw.lowercased()
        if lower == "entropy" || lower == "prefer_entropy" { return ("entropy", "entropy") }
        if lower == "ascii" || lower == "prefer_ascii" { return ("ascii", "ascii") }
        guard lower.hasPrefix("up_"), let range = lower.range(of: "_down_", range: lower.index(lower.startIndex, offsetBy: 3)..<lower.endIndex) else { throw AnywhereError.proxy(.sudoku, .invalidConfiguration(detail: "invalid ASCII mode")) }
        let up = String(lower[lower.index(lower.startIndex, offsetBy: 3)..<range.lowerBound])
        let down = String(lower[range.upperBound...])
        guard ["ascii", "entropy"].contains(up), ["ascii", "entropy"].contains(down) else { throw AnywhereError.proxy(.sudoku, .invalidConfiguration(detail: "invalid ASCII mode")) }
        return (up, down)
    }

    private static func tableHintFingerprint(key: String, mode: String, uplinkPattern: String, downlinkPattern: String) -> UInt32 {
        var data = Data("sudoku-table-hint".utf8)
        let uplink = uplinkPattern.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        let downlink = downlinkPattern.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        data.append(0)
        data.append(Data(key.utf8))
        data.append(0)
        data.append(Data(mode.utf8))
        data.append(0)
        data.append(Data(uplink.utf8))
        data.append(0)
        data.append(Data(downlink.utf8))
        let sum = sudokuSHA256(data)
        return (UInt32(sum[0]) << 24) | (UInt32(sum[1]) << 16) | (UInt32(sum[2]) << 8) | UInt32(sum[3])
    }
}

nonisolated struct SudokuPureDecoder {
    /// Hint indexes of an unfinished group, first one lowest.
    private var carriedHints: UInt32 = 0
    private var hintCount = 0
    private var pending = SudokuDataQueue()

    mutating func decode(_ data: Data, table: SudokuTable, limit: Int) throws -> Data {
        let outputLimit = max(0, limit)
        guard outputLimit > 0 else { return Data() }
        guard !data.isEmpty || !pending.isEmpty else { return Data() }
        if data.isEmpty { return pending.read(max: outputLimit) }
        let decoded = try SudokuBufferPool.makeData(capacity: max(1, (data.count + hintCount) / 4)) { rawOut in
            try data.withUnsafeBytes { rawInput in
                try decodeWindows(rawInput.bindMemory(to: UInt8.self), table: table, into: rawOut.baseAddress!.assumingMemoryBound(to: UInt8.self))
            }
        }
        pending.append(decoded)
        return pending.read(max: outputLimit)
    }

    /// Filters hints out of the wire a window at a time, compacting them branchlessly (a
    /// non-hint is stored over the next slot and not counted), then decodes whole groups.
    private mutating func decodeWindows(_ input: UnsafeBufferPointer<UInt8>, table: SudokuTable, into output: UnsafeMutablePointer<UInt8>) throws -> Int {
        let hintIdx = table.hintIdx
        let hintSets = table.hintSets
        var written = 0
        var consumed = 0
        try withUnsafeTemporaryAllocation(of: UInt8.self, capacity: 512) { hints in
            while consumed < input.count {
                let window = min(input.count - consumed, 256)
                var k = hintCount
                for i in 0..<k { hints[i] = UInt8(truncatingIfNeeded: carriedHints >> UInt32(8 * i)) }
                for i in consumed..<(consumed + window) {
                    let index = hintIdx[Int(input[i])]
                    hints[k & 511] = index
                    k += Int(index >> 7) ^ 1
                }
                consumed += window
                let groups = k >> 2
                for group in 0..<groups {
                    let h = 4 * group
                    let value = SudokuTable.decodeHints(hintSets, hints[h], hints[h + 1], hints[h + 2], hints[h + 3])
                    guard value >= 0 else {
                        hintCount = 0
                        throw AnywhereError.proxy(.sudoku, .protocolViolation(detail: "Sudoku decode failed"))
                    }
                    output[written] = UInt8(truncatingIfNeeded: value)
                    written += 1
                }
                hintCount = k & 3
                carriedHints = 0
                for i in 0..<hintCount { carriedHints |= UInt32(hints[4 * groups + i]) << UInt32(8 * i) }
            }
        }
        return written
    }
}

nonisolated struct SudokuPackedDecoder {
    private let padMarker: UInt8
    private var bitBuffer: UInt64 = 0
    private var bitCount = 0
    private var pending = SudokuDataQueue()

    init(table: SudokuTable) { padMarker = table.layout.padMarker }

    mutating func decode(_ data: Data, table: SudokuTable, limit: Int) throws -> Data {
        let outputLimit = max(0, limit)
        guard outputLimit > 0 else { return Data() }
        guard !data.isEmpty || !pending.isEmpty else { return Data() }
        if data.isEmpty { return pending.read(max: outputLimit) }
        let decoded = SudokuBufferPool.makeData(capacity: max(1, (data.count * 6 + bitCount) / 8)) { rawOut in
            data.withUnsafeBytes { rawInput in
                decodeGroups(rawInput.bindMemory(to: UInt8.self), table: table, into: rawOut.baseAddress!.assumingMemoryBound(to: UInt8.self))
            }
        }
        pending.append(decoded)
        return pending.read(max: outputLimit)
    }

    private mutating func decodeGroups(_ input: UnsafeBufferPointer<UInt8>, table: SudokuTable, into output: UnsafeMutablePointer<UInt8>) -> Int {
        let decodeGroup = table.decodeGroup
        var bitBuffer = self.bitBuffer
        var bitCount = self.bitCount
        var written = 0
        var index = 0
        while index < input.count {
            let b = input[index]
            index += 1
            let group = decodeGroup[Int(b)]
            guard group < 64 else {
                if b == padMarker {
                    bitBuffer = 0
                    bitCount = 0
                }
                continue
            }

            // Skip padding before probing a complete block. Reuse the
            // first lookup when only one group can be consumed.
            if bitCount == 0, index + 2 < input.count {
                let g2 = UInt16(decodeGroup[Int(input[index])])
                if g2 < 64 {
                    let g3 = UInt16(decodeGroup[Int(input[index + 1])])
                    let g4 = UInt16(decodeGroup[Int(input[index + 2])])
                    if (g3 | g4) < 64 {
                        let g1 = UInt16(group)
                        output[written] = UInt8(truncatingIfNeeded: (g1 << 2) | (g2 >> 4))
                        output[written + 1] = UInt8(truncatingIfNeeded: (g2 << 4) | (g3 >> 2))
                        output[written + 2] = UInt8(truncatingIfNeeded: (g3 << 6) | g4)
                        written += 3
                        index += 3
                        continue
                    }
                }
            }
            bitBuffer = (bitBuffer << 6) | UInt64(group)
            bitCount += 6
            while bitCount >= 8 {
                bitCount -= 8
                output[written] = UInt8(truncatingIfNeeded: bitBuffer >> UInt64(bitCount))
                bitBuffer = bitCount == 0 ? 0 : bitBuffer & ((UInt64(1) << UInt64(bitCount)) - 1)
                written += 1
            }
        }
        self.bitBuffer = bitBuffer
        self.bitCount = bitCount
        return written
    }
}
