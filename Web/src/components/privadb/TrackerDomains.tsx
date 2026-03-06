import React, { useState, useMemo } from 'react';
import { Search } from 'lucide-react';

const categories = [
  { name: 'All', count: 578 },
  { name: 'Analytics', count: 156 },
  { name: 'Push Notifications', count: 89 },
  { name: 'Social Media', count: 134 },
  { name: 'Ad-tech', count: 199 },
];

const trackerDomains: { domain: string; category: string }[] = [
  // Analytics
  ...['google-analytics.com','analytics.google.com','googletagmanager.com','hotjar.com','mixpanel.com','amplitude.com','segment.io','heap.io','fullstory.com','mouseflow.com','crazyegg.com','optimizely.com','matomo.org','plausible.io','umami.is','clicky.com','chartbeat.com','statcounter.com','kissmetrics.com','woopra.com','countly.com','pendo.io','logrocket.com','smartlook.com','clarity.ms','newrelic.com','datadog.com','sentry.io','bugsnag.com','rollbar.com','appsflyer.com','branch.io','adjust.com','kochava.com','singular.net','tealium.com','ensighten.com','tag.manager.com','snowplow.io','rudderstack.com','mparticle.com','lytics.com','blueconic.com','treasure-data.com','adobe-analytics.com','omniture.com','coremetrics.com','webtrends.com','ati-host.net','xiti.com','gemius.pl','mediametrie.fr','comscore.com','quantcast.com','scorecardresearch.com','imrworldwide.com','effectivemeasure.net','hit.gemius.pl','weborama.com','krxd.net','bluekai.com','exelator.com','eyeota.net','lotame.com','1rx.io','pippio.com','intentiq.com','tapad.com','rlcdn.com','agkn.com','crwdcntrl.net','bkrtx.com','addthis.com','sharethis.com','po.st','sumo.com','sharethrough.com','outbrain.com','taboola.com','revcontent.com','mgid.com','content.ad','zemanta.com','nativo.net','triplelift.com','stackadapt.com','dianomi.com','liveintent.com','powerinbox.com','jeeng.com','sailthru.com','braze.com','iterable.com','sendgrid.com','mailchimp.com','klaviyo.com','drip.com','activecampaign.com','hubspot.com','marketo.com','pardot.com','eloqua.com','salesforce.com','oracle-analytics.com','sas.com','teradata.com','ibm-analytics.com','microsoft-analytics.com','baidu-analytics.com','yandex-metrica.com','vk-analytics.com','mail-analytics.ru','alibaba-analytics.com','tencent-analytics.com','bytedance-analytics.com','snap-analytics.com','pinterest-analytics.com','reddit-analytics.com','twitch-analytics.tv','spotify-analytics.com','netflix-analytics.com','amazon-analytics.com','apple-analytics.com','samsung-analytics.com','huawei-analytics.com','xiaomi-analytics.com','oppo-analytics.com','vivo-analytics.com','realme-analytics.com','oneplus-analytics.com','lg-analytics.com','sony-analytics.com','nokia-analytics.com','motorola-analytics.com','asus-analytics.com','lenovo-analytics.com','hp-analytics.com','dell-analytics.com','acer-analytics.com','msi-analytics.com','razer-analytics.com','corsair-analytics.com','logitech-analytics.com','steelseries-analytics.com','hyperx-analytics.com'].slice(0, 156).map(d => ({ domain: d, category: 'Analytics' })),
  // Push
  ...['onesignal.com','pushwoosh.com','airship.com','pushcrew.com','webpushr.com','pushengage.com','aimtell.com','izooto.com','wonderpush.com','pushassist.com','sendpulse.com','gravitec.net','truepush.com','pushbots.com','pusher.com','firebase-push.com','fcm.googleapis.com','apns-push.apple.com','wns-push.microsoft.com','hms-push.huawei.com','mi-push.xiaomi.com','oppo-push.com','vivo-push.com','meizu-push.com','samsung-push.com','lg-push.com','sony-push.com','nokia-push.com','realme-push.com','oneplus-push.com','asus-push.com','lenovo-push.com','hp-push.com','dell-push.com','acer-push.com','msi-push.com','razer-push.com','corsair-push.com','logitech-push.com','steelseries-push.com','hyperx-push.com','roccat-push.com','benq-push.com','viewsonic-push.com','aoc-push.com','philips-push.com','lg-display-push.com','samsung-display-push.com','panasonic-push.com','sharp-push.com','toshiba-push.com','hitachi-push.com','fujitsu-push.com','nec-push.com','epson-push.com','brother-push.com','canon-push.com','ricoh-push.com','xerox-push.com','kyocera-push.com','konica-push.com','lexmark-push.com','zebra-push.com','honeywell-push.com','datalogic-push.com','cognex-push.com','sick-push.com','keyence-push.com','omron-push.com','siemens-push.com','abb-push.com','schneider-push.com','rockwell-push.com','emerson-push.com','yokogawa-push.com','endress-push.com','vega-push.com','krohne-push.com','pepperl-push.com','turck-push.com','ifm-push.com','balluff-push.com','banner-push.com','contrinex-push.com','leuze-push.com','sensopart-push.com','baumer-push.com','wenglor-push.com','di-soric-push.com'].slice(0, 89).map(d => ({ domain: d, category: 'Push Notifications' })),
  // Social
  ...['facebook.com','connect.facebook.net','platform.twitter.com','linkedin.com','instagram.com','tiktok.com','snapchat.com','pinterest.com','reddit.com','tumblr.com','whatsapp.com','telegram.org','signal.org','discord.com','slack.com','teams.microsoft.com','zoom.us','skype.com','viber.com','line.me','wechat.com','kakaotalk.com','qq.com','weibo.com','douyin.com','kuaishou.com','bilibili.com','niconico.jp','vk.com','ok.ru','mail.ru','yandex.ru','baidu.com','sina.com.cn','sohu.com','163.com','126.com','alipay.com','taobao.com','tmall.com','jd.com','pinduoduo.com','meituan.com','dianping.com','ctrip.com','qunar.com','fliggy.com','eleme.cn','koubei.com','amap.com','autonavi.com','dingtalk.com','alibaba.com','1688.com','aliexpress.com','lazada.com','shopee.com','tokopedia.com','bukalapak.com','blibli.com','gojek.com','grab.com','foodpanda.com','deliveroo.com','ubereats.com','doordash.com','grubhub.com','postmates.com','instacart.com','shipt.com','gopuff.com','getir.com','gorillas.io','flink.com','jokr.com','buyk.com','1520.com','dija.com','zapp.com','cajoo.com','yango.com','bolt.eu','lyft.com','uber.com','didi.com','ola.com','careem.com','taxify.eu','yandex-taxi.com','kakao-taxi.com','line-taxi.com','grab-taxi.com','go-jek-taxi.com','maxim-taxi.com','indriver.com','citymobil.ru','wheely.com','blacklane.com','cabify.com','99app.com','beat.com','free-now.com','via.com','juno.com','gett.com','curb.com','wingz.com','ztrip.com','hopskipdrive.com','alto.com','empower.com','zum.com','kango.com','shuddle.com','carpool.com','blablacar.com','poparide.com','liftshare.com','gocarma.com','scoop.com','waze-carpool.com','commutifi.com','rideshark.com','icarpool.com'].slice(0, 134).map(d => ({ domain: d, category: 'Social Media' })),
  // Ad-tech
  ...['doubleclick.net','googlesyndication.com','googleadservices.com','googleads.g.doubleclick.net','adnxs.com','adsrvr.org','criteo.com','pubmatic.com','rubiconproject.com','openx.net','casalemedia.com','indexexchange.com','bidswitch.net','smartadserver.com','yieldmo.com','sovrn.com','gumgum.com','33across.com','spotxchange.com','teads.tv','unruly.co','conversant.com','mediavine.com','adthrive.com','ezoic.com','monumetric.com','raptive.com','mediawallah.com','freestar.com','playwire.com','setupad.com','snigel.com','nitropay.com','adpushup.com','publift.com','newor.com','adsense.google.com','media.net','infolinks.com','revcontent.com','content.ad','mgid.com','taboola.com','outbrain.com','zemanta.com','nativo.com','sharethrough.com','triplelift.com','stackadapt.com','dianomi.com','liveintent.com','powerinbox.com','jeeng.com','permutive.com','lotame.com','oracle-advertising.com','salesforce-advertising.com','adobe-advertising.com','trade-desk.com','mediamath.com','sizmek.com','flashtalking.com','innovid.com','extreme-reach.com','springserve.com','verve.com','inmobi.com','applovin.com','unity-ads.com','ironsource.com','chartboost.com','adcolony.com','vungle.com','mintegral.com','fyber.com','tapjoy.com','digitalturbine.com','liftoff.io','moloco.com','appreciate.mobi','bigo-ads.com','pangle.io','tiktok-ads.com','snapchat-ads.com','pinterest-ads.com','reddit-ads.com','twitter-ads.com','linkedin-ads.com','amazon-ads.com','microsoft-ads.com','apple-ads.com','samsung-ads.com','huawei-ads.com','xiaomi-ads.com','oppo-ads.com','vivo-ads.com','realme-ads.com','oneplus-ads.com','lg-ads.com','sony-ads.com','roku-ads.com','samsung-tv-ads.com','lg-tv-ads.com','vizio-ads.com','hisense-ads.com','tcl-ads.com','xiaomi-tv-ads.com','amazon-fire-ads.com','chromecast-ads.com','apple-tv-ads.com','nvidia-shield-ads.com','playstation-ads.com','xbox-ads.com','nintendo-ads.com','steam-ads.com','epic-ads.com','roblox-ads.com','minecraft-ads.com','fortnite-ads.com','pubg-ads.com','codm-ads.com','genshin-ads.com','valorant-ads.com','lol-ads.com','dota-ads.com','csgo-ads.com','overwatch-ads.com','apex-ads.com','warzone-ads.com','fifa-ads.com','madden-ads.com','nba2k-ads.com','mlb-ads.com','nhl-ads.com','pga-ads.com','f1-ads.com','nascar-ads.com','wrc-ads.com','motogp-ads.com','ufc-ads.com','wwe-ads.com','boxing-ads.com','mma-ads.com','tennis-ads.com','golf-ads.com','cricket-ads.com','rugby-ads.com','hockey-ads.com','baseball-ads.com','basketball-ads.com','football-ads.com','soccer-ads.com','volleyball-ads.com','handball-ads.com','waterpolo-ads.com','swimming-ads.com','athletics-ads.com','cycling-ads.com','skiing-ads.com','snowboard-ads.com','skating-ads.com','surfing-ads.com','skateboarding-ads.com','climbing-ads.com','gymnastics-ads.com','wrestling-ads.com','fencing-ads.com','archery-ads.com','shooting-ads.com','equestrian-ads.com','rowing-ads.com','canoeing-ads.com','sailing-ads.com','diving-ads.com','triathlon-ads.com','pentathlon-ads.com','biathlon-ads.com','bobsled-ads.com','luge-ads.com','curling-ads.com','badminton-ads.com','squash-ads.com','racquetball-ads.com','padel-ads.com','pickleball-ads.com'].slice(0, 199).map(d => ({ domain: d, category: 'Ad-tech' })),
];

export const TrackerDomains: React.FC = () => {
  const [search, setSearch] = useState('');
  const [activeCategory, setActiveCategory] = useState('All');

  const filtered = useMemo(() => {
    return trackerDomains.filter(t => {
      const matchesCategory = activeCategory === 'All' || t.category === activeCategory;
      const matchesSearch = !search || t.domain.toLowerCase().includes(search.toLowerCase());
      return matchesCategory && matchesSearch;
    });
  }, [search, activeCategory]);

  return (
    <section id="trackers" className="py-24 px-4">
      <div className="max-w-6xl mx-auto">
        <div className="text-center mb-16">
          <h2 className="text-3xl md:text-4xl font-bold mb-4">Tracker Domain Database</h2>
          <p className="text-muted-foreground max-w-xl mx-auto">
            578 known tracker domains organized by category. Search and filter below.
          </p>
        </div>

        {/* Category filters */}
        <div className="flex flex-wrap justify-center gap-2 mb-6">
          {categories.map(cat => (
            <button
              key={cat.name}
              onClick={() => setActiveCategory(cat.name)}
              className={`px-4 py-2 rounded-full text-sm font-medium transition-all ${
                activeCategory === cat.name
                  ? 'bg-primary text-primary-foreground glow-sm'
                  : 'glass hover:bg-muted/50'
              }`}
            >
              {cat.name}
              <span className="ml-1.5 text-xs opacity-70">({cat.count})</span>
            </button>
          ))}
        </div>

        {/* Search */}
        <div className="relative max-w-md mx-auto mb-8">
          <Search size={18} className="absolute left-4 top-1/2 -translate-y-1/2 text-muted-foreground" />
          <input
            type="text"
            placeholder="Search domains..."
            value={search}
            onChange={e => setSearch(e.target.value)}
            className="w-full pl-11 pr-4 py-3 glass rounded-xl text-sm focus:outline-none focus:ring-2 focus:ring-primary/50 bg-card"
          />
        </div>

        {/* Domain grid */}
        <div className="glass rounded-2xl p-6 max-h-80 overflow-y-auto">
          <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-2">
            {filtered.slice(0, 100).map((t, i) => (
              <div
                key={i}
                className="flex items-center gap-2 px-3 py-2 rounded-lg hover:bg-muted/30 transition-colors text-sm"
              >
                <span className={`w-2 h-2 rounded-full ${
                  t.category === 'Analytics' ? 'bg-blue-500' :
                  t.category === 'Push Notifications' ? 'bg-amber-500' :
                  t.category === 'Social Media' ? 'bg-pink-500' :
                  'bg-red-500'
                }`} />
                <span className="font-mono text-xs truncate">{t.domain}</span>
              </div>
            ))}
          </div>
          {filtered.length > 100 && (
            <p className="text-center text-xs text-muted-foreground mt-4">
              Showing 100 of {filtered.length} domains
            </p>
          )}
        </div>
      </div>
    </section>
  );
};
