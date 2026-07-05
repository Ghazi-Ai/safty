#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
مدقق وموحّد بيانات حوادث السلامة — data_audit.py (الإصدار 2 — بعد التدقيق العدائي)

يوحّد: أسماء الطرق، أسماء المركبات (اسم الموديل بدون الشركة)، الجهات المباشرة.
لا يغيّر: عدد السجلات، الوفيات، الإصابات، التواريخ، الإحداثيات.

الاستخدام:
  python3 data_audit.py               # تقرير فقط
  python3 data_audit.py --apply       # يطبّق ويكتب incidents_data.json + audit_changes.json
"""
import json, re, sys, unicodedata
from collections import Counter

APPLY = '--apply' in sys.argv
SRC = 'incidents_data.json'

# ═══════════ إصلاحات جزئية داخل حقل المركبة (نصوص يكسرها التقسيم على "-") ═══════════
# تُطبَّق بالترتيب قبل أي تقسيم — الأسماء المركبة تُكتب بدون شرطات حتى لا تنقسم
RAW_VEHICLE_SUBSTR = [
    (re.compile(r'سيارة\s+سيدان\s*-\s*4\s*\n?\s*أبواب'), 'سيدان 4 أبواب'),
    (re.compile(r'شاحن[هة]\s*-\s*محورين'), 'شاحنة محورين'),
    (re.compile(r'3\s*محاور\s*\(\s*شاحنة\s*/\s*قلاب\s*\)'), 'شاحنة قلاب 3 محاور'),
    (re.compile(r'CR\s*-\s*V', re.I), 'CRV'),
    (re.compile(r'شاحنة نقل خفيف\s*\n?\s*\(ونيت\)\s*صنع\s*ايسوز'), 'ونيت'),
]
RAW_AUTH_FIXES = {
    'أمن الطرق الحليفة \n شرطة بدع بن خلف': 'أمن الطرق - الحليفة + شرطة بدع بن خلف',
}

# ═══════════ مرادفات مؤكدة (من التدقيق العدائي — نفس الكيان بأدلة) ═══════════
SYN_ROAD = {
    'انبوان / سقف': 'سقف انبوان',
    'الكتيب / ساحوت': 'الكتيب - ساحوت', 'ساحوت - الكتيب': 'الكتيب - ساحوت',
    'الثمامية / المعرش': 'المعرش / الثمامية',
    'النحيتية / البعايث': 'البعايث / النحيتية',
    'الحائط / خيبر': 'خيبر / الحائط', 'خبير / الحائط': 'خيبر / الحائط',
    'الحائط - الشملي': 'الشملي / الحائط',
    'الغزالة / الروضة': 'الروضة / الغزالة',
    'حائل / الجوف': 'حائل الجوف السريع',
    'حائل رفحاء السريع': 'حائل رفحاء',
    'حائل / المدينة المنورة': 'حائل المدينة المباشر',
    'حائل المدينة المنورة المباشر': 'حائل المدينة المباشر',
    'شعيبة المياة': 'الاجفر شعيبة المياه', 'شعيبة المياه': 'الاجفر شعيبة المياه',
    'حائل-حويان-القصيصة': 'عقلة - حويان - القصيصه',
    'المندسة الجاف': 'المندسة الجلف',
    'جانيين / الناصريه': 'جانين الناصرية',
    # تصحيح إملاء الأسماء القانونية
    'حائل جبه': 'حائل جبة',
    'الاجفر شعيبة المياة': 'الاجفر شعيبة المياه',
}
SYN_AUTH = {
    'لايوجد': 'لا يوجد',
    'مرورالسفن': 'مرور السفن',
    'مرورحائل': 'مرور حائل',
    'امن طرق': 'امن الطرق',
    'امن طرق عريجا': 'امن طرق عريجاء',
    'أمن الطرق الحليفه': 'أمن الطرق - الحليفة',
    'أمن طرق الحليفة': 'أمن الطرق - الحليفة',
    'أمن طرق - الحليفه': 'أمن الطرق - الحليفة',
    'امن طرق الحليفة': 'أمن الطرق - الحليفة',
    'أمن الطرق - الحليفة العليا': 'أمن الطرق الحليفة العليا',
    'أمن الطرق - الحليفة العلياء': 'أمن الطرق الحليفة العليا',
    'أمن الطريق - الحليفة العليا': 'أمن الطرق الحليفة العليا',
    'أمن الطرق الحليفه العليا': 'أمن الطرق الحليفة العليا',
    'امن الطرق الهويدي': 'امن طرق الهويدي',
    'أمن الطرق - الهويدي': 'امن طرق الهويدي',
    'أمن طرق - الهويدي': 'امن طرق الهويدي',
    'أمن الطرق الدارة': 'امن طرق الدارة',
    'امن الطرق الشنان': 'امن طرق الشنان',
    'امن طرق ومرورجبة': 'امن طرق ومرور جبة',
    'امن طرق الداره +مرور الغزالة': 'امن طرق الدارة + مرور الغزالة',
}
SYN_VEH = {
    'هايلكس': 'هايلوكس',
    'تريلة': 'تريلا', 'تريله': 'تريلا', 'تريلاء': 'تريلا',
    'داتسون': 'ددسن', 'دادسن': 'ددسن', 'داتسن': 'ددسن', 'دادسون': 'ددسن', 'نيسان ( ددسن)': 'ددسن',
    'كورلا': 'كورولا', 'كوريلا': 'كورولا', 'كرولا': 'كورولا', 'كورورلا': 'كورولا',
    'لاند كروزر': 'لاندكروزر', 'لاندكروز': 'لاندكروزر', 'جيب لاندكروزر': 'لاندكروزر',
    'افلون': 'افالون',
    'فورشنر': 'فورتشنر', 'فور شنر': 'فورتشنر', 'فورتشينر': 'فورتشنر', 'فورتشتر': 'فورتشنر', 'فوشنر': 'فورتشنر',
    'اوبتماء': 'اوبتيما', 'اوبتيماء': 'اوبتيما', 'أوبتيما': 'اوبتيما',
    'توريس': 'تورس', 'فوردتورس': 'تورس',
    'ايسوزوا': 'ايسوزو', 'ايسيزو': 'ايسوزو', 'اسيزو': 'ايسوزو', 'سيزو': 'ايسوزو',
    'سيزوو': 'ايسوزو', 'الايسوزو': 'ايسوزو',
    'دينه': 'دينا', 'ديانا': 'دينا',
    'ياريس': 'يارس',
    'جمس يكون': 'يوكن', 'جمس يوكن': 'يوكن',
    'سلفاردو': 'سلفرادو',
    'جينسس': 'جينسيس',
    'النتراء': 'النترا', 'انترا': 'النترا',
    'كورد': 'اكورد', 'اكورود': 'اكورد', 'أكورد': 'اكورد',
    'شيفرولية': 'شفروليه', 'شفرولية': 'شفروليه',
    'هايس': 'هايس',
    'لوبيد': 'لوبد', 'لوبز': 'لوبد',
    'بيك اب': 'بكب', 'بك اب': 'بكب',
    'نييسان صني': 'صني', 'صني ( نيسان)': 'صني',
    'كياء': 'كيا',
    'شان جان': 'شانجان',
    'مستبيشو': 'ميتسوبيشي', 'موستبيشي': 'ميتسوبيشي', 'متسوبيشي': 'ميتسوبيشي',
    'فلفو': 'فولفو',
    'اكسبيدشن': 'اكسبديشن',
    'اسكويا': 'سكويا',
    'رنج روف': 'رنج',
    'سيدان صنع تويوتا طراز كامري': 'كامري',
    'سيدان صنع تويوتا طراز كورولا': 'كورولا',
    'نوع سيدان صنع كيا طراز كادينزا': 'كادينزا',
    'رياضيه متعددة الاستعمالات صنع شيري طراز تيجو': 'تيجو',
    'رياضيه متعدده الاستعمالات صنع سوزوكي': 'سوزوكي',
    'شاحنة نقل خفيف (ونيت) صنع ايسوز': 'ونيت',
    '(ونيت) صنع ايسوز': 'ونيت',
    'شاحنة صغيرة (ونيت)': 'ونيت',
    'وانيت': 'ونيت',
    'رياضيه متعدده الاستعمالات صنع': 'رياضية متعددة الاستعمالات',
    'رياضيه متعدده الاستعمالات': 'رياضية متعددة الاستعمالات',
    'رياضيه متعددة الاستعمالات': 'رياضية متعددة الاستعمالات',
    'تريلة نقل': 'تريلا نقل',
    'راس تريلة': 'راس تريلا',
}

# ═══════════ أدوات التطبيع ═══════════
AR_DIGITS = str.maketrans('٠١٢٣٤٥٦٧٨٩', '0123456789')

def norm_key(s):
    """مفتاح مقارنة: همزات موحدة، ة=ه، ى=ي، ئ=ي، ؤ=و، أرقام موحدة، مسافات مفردة"""
    s = unicodedata.normalize('NFC', s.strip())
    s = s.translate(AR_DIGITS)
    s = re.sub(r'[أإآٱ]', 'ا', s)
    s = re.sub(r'ى', 'ي', s)
    s = re.sub(r'ئ', 'ي', s)
    s = re.sub(r'ؤ', 'و', s)
    s = re.sub(r'ة', 'ه', s)
    s = re.sub(r'ـ+', '', s)
    s = re.sub(r'[.,،]+$', '', s.strip())
    s = re.sub(r'\s+', ' ', s)
    return s.strip().lower()

def road_key(s):
    """للطرق: الفواصل (/ - \\) كلها تعادل مسافة — 'حائل/العلا' = 'حائل - العلا' = 'حائل العلا'"""
    k = norm_key(s)
    k = re.sub(r'\s*[/\\\-]+\s*', ' ', k)
    return re.sub(r'\s+', ' ', k).strip()

BRANDS = ['تويوتا','تايوتا','تيوتا','هيونداي','هونداي','هوندا','نيسان','نييسان',
          'شفروليه','شيفروليه','شفرولية','شيفرولية','سيفروليه','شفر',
          'فورد','كيا','مازدا','ميتسوبيشي','متسوبيشي','جي ام سي','جمس','لكزس',
          'مرسيدس','بي ام دبليو','دوج','دودج','سوزوكي','ايسوزو','ايسوزوا','اسوزو',
          'رينو','هينو','مان','فولفو','سكانيا','داف','شانجان','جيلي','ام جي','هافال']
BRAND_KEYS = sorted({norm_key(b) for b in BRANDS}, key=len, reverse=True)

def strip_brand(k):
    changed = True
    while changed:
        changed = False
        for b in BRAND_KEYS:
            if k.startswith(b + ' '):
                k = k[len(b)+1:].strip(); changed = True
            elif k.endswith(' ' + b):
                k = k[:-(len(b)+1)].strip(); changed = True
    return k.strip()

def vkey(s):
    k = strip_brand(norm_key(s))
    return k if k else norm_key(s)

def split_vehicles(s):
    return [v.strip() for v in re.split(r'[+\-،,/_\n]+', s or '') if len(v.strip()) > 1]

def display_road(s):
    s = re.sub(r'\s*[/\\]\s*', ' / ', s.strip())
    return re.sub(r'\s+', ' ', s)

def display_clean(s):
    s = re.sub(r'[.،,]+$', '', s.strip())
    return re.sub(r'\s+', ' ', s)

def strip_brand_display(s):
    """يزيل اسم الشركة من شكل العرض مع الحفاظ على إملاء الموديل"""
    words = display_clean(s).split(' ')
    while len(words) > 1 and norm_key(words[0]) in BRAND_KEYS:
        words = words[1:]
    while len(words) > 1 and norm_key(words[-1]) in BRAND_KEYS:
        words = words[:-1]
    out = ' '.join(words)
    return out if out else display_clean(s)

def apply_syn(val, syn):
    """يطبق المرادفات حتى الاستقرار (سلاسل التحويل)"""
    seen = set()
    while val in syn and val not in seen:
        seen.add(val); val = syn[val]
    return val

# ═══════════ بناء خرائط التوحيد ═══════════
def build_map(values, keyfn, dispfn, brandless=False):
    clusters = {}
    for name, n in values.items():
        clusters.setdefault(keyfn(name), []).append((name, n))
    mapping = {}
    for k, members in clusters.items():
        pool = members
        if brandless:
            bl = [(m, n) for m, n in members if norm_key(m) == k]
            pool = bl if bl else members
        top = sorted(pool, key=lambda x: (-x[1], len(x[0]), x[0]))[0][0]
        canon = strip_brand_display(top) if brandless else dispfn(top)
        for name, _ in members:
            if name != canon:
                mapping[name] = canon
    return mapping, clusters

def main():
    data = json.load(open(SRC, encoding='utf-8'))
    before = {
        'records': len(data),
        'deaths': sum(r.get('deaths', 0) for r in data),
        'injuries': sum(r.get('injuries', 0) for r in data),
        'total_incidents': sum(r.get('total_incidents', 1) if r.get('is_aggregate') else 1 for r in data),
    }

    # إصلاح القيم الخام المكسورة أولاً
    for r in data:
        vt = r.get('vehicle_type', '')
        if vt:
            for pat, rep in RAW_VEHICLE_SUBSTR:
                vt = pat.sub(rep, vt)
            r['vehicle_type'] = vt
        au = r.get('authority', '')
        if au in RAW_AUTH_FIXES: r['authority'] = RAW_AUTH_FIXES[au]

    roads = Counter(r['road_name'] for r in data if r.get('road_name'))
    auths = Counter(r['authority'] for r in data if r.get('authority'))
    vtokens = Counter()
    for r in data:
        for v in split_vehicles(r.get('vehicle_type', '')):
            vtokens[v] += 1

    road_map, rc = build_map(roads, road_key, display_road)
    auth_map, _  = build_map(auths, norm_key, display_clean)
    veh_map, vc  = build_map(vtokens, vkey, display_clean, brandless=True)

    def final_road(v):
        v = road_map.get(v, display_road(v)); return apply_syn(v, SYN_ROAD)
    def final_auth(v):
        v = auth_map.get(v, display_clean(v)); return apply_syn(v, SYN_AUTH)
    def final_vtok(t):
        t = veh_map.get(t, display_clean(t))
        t = apply_syn(t, SYN_VEH)
        return apply_syn(strip_brand_display(t), SYN_VEH)

    n_roads = len({final_road(x) for x in roads})
    n_veh   = len({final_vtok(x) for x in vtokens})
    n_auth  = len({final_auth(x) for x in auths})
    print(f"■ الطرق:    {len(roads)} خام → {n_roads} موحّد")
    print(f"■ المركبات: {len(vtokens)} خام → {n_veh} موحّد")
    print(f"■ الجهات:   {len(auths)} خام → {n_auth} موحّد")

    if not APPLY:
        print("\n— تقرير فقط. للتطبيق: python3 data_audit.py --apply —")
        return

    changes = {'roads': {}, 'vehicles': {}, 'authorities': {}}
    for r in data:
        rn = r.get('road_name', '')
        if rn:
            nv = final_road(rn)
            if nv != rn: changes['roads'][rn] = nv; r['road_name'] = nv
        au = r.get('authority', '')
        if au:
            nv = final_auth(au)
            if nv != au: changes['authorities'][au] = nv; r['authority'] = nv
        vt = r.get('vehicle_type', '')
        if vt:
            parts = split_vehicles(vt)
            if parts:
                newparts = []
                for p in parts:
                    np = final_vtok(p)
                    if p != np: changes['vehicles'][p] = np
                    newparts.append(np)      # نُبقي المكرر: حادث بين كامريتين = مركبتان
                nv = ' - '.join(newparts)
            else:
                nv = display_clean(vt)
            if nv != vt: r['vehicle_type'] = nv

    after = {
        'records': len(data),
        'deaths': sum(r.get('deaths', 0) for r in data),
        'injuries': sum(r.get('injuries', 0) for r in data),
        'total_incidents': sum(r.get('total_incidents', 1) if r.get('is_aggregate') else 1 for r in data),
    }
    assert before == after, f"فشل فحص السلامة! قبل={before} بعد={after}"

    json.dump(data, open(SRC, 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
    json.dump(changes, open('audit_changes.json', 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
    print(f"\n✅ طُبّق التوحيد — طرق: {len(changes['roads'])} | مركبات: {len(changes['vehicles'])} | جهات: {len(changes['authorities'])}")
    print(f"   فحوص السلامة: السجلات={after['records']} الوفيات={after['deaths']} الإصابات={after['injuries']} ✓")

if __name__ == '__main__':
    main()
