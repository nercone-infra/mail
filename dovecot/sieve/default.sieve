require ["body","copy","fileinto","imap4flags"];
# rule:[manual-spam]
if anyof (header :contains "from" "@startnovada.com", header :contains "Reply-To" "@wyss-hansjorg.org", header :contains "from" "@xomyx.com", header :contains "from" "Omvarma546@outlook.com", header :contains "from" "anikasales156@outlook.com", header :contains "from" "creattopweb@hotmail.com", header :contains "from" "riotthomas2568@gmail.com", header :contains "from" "SebastianNolan834V@hotmail.com", header :contains "from" "Joanneust45@outlook.com", header :contains "from" "deeznuts01699610@gmail.com")
{
	addflag "\\Seen";
	fileinto "Junk";
	stop;
}
# rule:[delivery-failure]
if header :contains "from" "MAILER-DAEMON@mx.nercone.dev"
{
	fileinto "delivery-failure";
	stop;
}
# rule:[t3tra]
if anyof (header :contains "subject" "t3tra", header :contains "from" "t3tra", header :contains "to" "t3tra", header :contains "cc" "t3tra", body :text :contains "t3tra")
{
	fileinto :copy "t3tra";
}
# rule:[adult]
if header :contains "from" "v-mail@dmm.co.jp"
{
	discard;
	stop;
}
# rule:[mention/full-name]
if anyof (body :text :contains "Kamiyama", body :text :contains "Chiaki", body :text :contains "神山", body :text :contains "千暁")
{
	fileinto :copy "mention.full-name";
}
# rule:[mailinglist/linux/quic]
if anyof (header :contains "from" "quic@lists.linux.dev", header :contains "to" "quic@lists.linux.dev", header :contains "cc" "quic@lists.linux.dev")
{
	fileinto :copy "mailinglist.linux.quic";
}
# rule:[mailinglist/linux/crypto]
if anyof (header :contains "from" "linux-crypto@vger.kernel.org", header :contains "cc" "linux-crypto@vger.kernel.org", header :contains "to" "linux-crypto@vger.kernel.org")
{
	addflag "\\Seen";
	fileinto :copy "mailinglist.linux.crypto";
}
# rule:[mailinglist/linux/cve-announce]
if anyof (header :contains "from" "cve@kernel.org", header :contains "cc" "cve@kernel.org", header :contains "to" "cve@kernel.org")
{
	addflag "\\Seen";
	fileinto :copy "mailinglist.linux.cve-announce";
	fileinto "mailinglist.linux";
	stop;
}
# rule:[mailinglist/linux/kernel-announce]
if anyof (header :contains "from" "linux-kernel-announce@vger.kernel.org", header :contains "cc" "linux-kernel-announce@vger.kernel.org", header :contains "to" "linux-kernel-announce@vger.kernel.org")
{
	fileinto :copy "mailinglist.linux.kernel-announce";
}
# rule:[mailinglist/linux/kernel]
if anyof (header :contains "from" "linux-kernel@vger.kernel.org", header :contains "cc" "linux-kernel@vger.kernel.org", header :contains "to" "linux-kernel@vger.kernel.org")
{
	addflag "\\Seen";
	fileinto "mailinglist.linux.kernel";
	stop;
}
# rule:[mailinglist/linux]
if anyof (header :contains "from" "@vger.kernel.org", header :contains "cc" "@vger.kernel.org", header :contains "to" "@vger.kernel.org")
{
	addflag "\\Seen";
	fileinto "mailinglist.linux";
	stop;
}
# rule:[discussion/fedora]
if header :contains "from" "notifications@fedoraproject.discoursemail.com"
{
	fileinto "discussion.fedora";
	stop;
}
# rule:[discussion/github]
if header :contains "from" "notifications@github.com"
{
	fileinto "discussion.github";
	stop;
}
# rule:[discussion/google]
if header :contains "from" "no-reply@discuss.google.dev"
{
	fileinto "discussion.google";
	stop;
}
# rule:[discussion/python]
if header :contains "from" "notifications@python1.discoursemail.com"
{
	fileinto "discussion.python";
	stop;
}
# rule:[discussion/shapr3d]
if header :contains "from" "notifications@shapr3d.discoursemail.com"
{
	fileinto "discussion.shapr3d";
	stop;
}
# rule:[mailinglist/adobe]
if anyof (header :contains "from" "mail@e.adobe.com", header :contains "from" "mail@mail.adobe.com")
{
	fileinto "mailinglist.adobe";
	stop;
}
# rule:[mailinglist/almalinux]
if header :contains "from" "@lists.almalinux.org"
{
	fileinto "mailinglist.almalinux";
	stop;
}
# rule:[mailinglist/autodesk]
if header :contains "from" "noreply@autodesk.com"
{
	fileinto "mailinglist.autodesk";
	stop;
}
# rule:[mailinglist/aws]
if header :contains "from" "invoicing@aws.com"
{
	fileinto "mailinglist.aws";
	stop;
}
# rule:[mailinglist/aws/marketplace]
if header :contains "from" "no-reply@marketplace.aws"
{
	fileinto "mailinglist.aws.marketplace";
	stop;
}
# rule:[mailinglist/cloudflare]
if anyof (header :contains "from" "cloudflare.com", header :contains "from" "noreply@notify.cloudflare.com")
{
	fileinto "mailinglist.cloudflare";
	stop;
}
# rule:[mailinglist/discord]
if header :contains "from" "noreply@discord.com"
{
	fileinto "mailinglist.discord";
	stop;
}
# rule:[mailinglist/dmm]
if header :contains "from" "v-mail@dmm.com"
{
	fileinto "mailinglist.dmm";
	stop;
}
# rule:[mailinglist/google]
if header :contains "from" "no-reply@google.com"
{
	fileinto "mailinglist.google";
	stop;
}
# rule:[mailinglist/google/findhub]
if header :contains "from" "noreply-findhub@google.com"
{
	fileinto "mailinglist.google.findhub";
	stop;
}
# rule:[mailinglist/google/play]
if header :contains "from" "googleplay-noreply@google.com"
{
	fileinto "mailinglist.google.play";
	stop;
}
# rule:[mailinglist/google/search-console]
if header :contains "from" "sc-noreply@google.com"
{
	fileinto "mailinglist.google.search-console";
	stop;
}
# rule:[mailinglist/google/wallet]
if header :contains "from" "googlewallet-noreply@google.com"
{
	fileinto "mailinglist.google.wallet";
	stop;
}
# rule:[mailinglist/hackerone]
if header :contains "from" "hackers@hackerone.com"
{
	fileinto "mailinglist.hackerone";
	stop;
}
# rule:[mailinglist/ikea]
if header :contains "from" "ikea@news.email.ikea.jp"
{
	fileinto "mailinglist.ikea";
	stop;
}
# rule:[mailinglist/instatus]
if header :contains "from" "ali@instatus.com"
{
	fileinto "mailinglist.instatus";
	stop;
}
# rule:[mailinglist/kit]
if header :contains "from" "help@convertkit.com"
{
	fileinto "mailinglist.kit";
	stop;
}
# rule:[mailinglist/microsoft/account]
if header :contains "from" "MicrosoftAccount@emailnotifications.microsoft.com"
{
	fileinto "mailinglist.microsoft.account";
	stop;
}
# rule:[mailinglist/microsoft/windows]
if header :contains "from" "Windows@notificationemails.microsoft.com"
{
	fileinto "mailinglist.microsoft.windows";
	stop;
}
# rule:[mailinglist/mintlify]
if header :contains "from" "han@mintlify.com"
{
	fileinto "mailinglist.mintlify";
	stop;
}
# rule:[mailinglist/nvidia]
if header :contains "from" "news@nvidia.com"
{
	fileinto "mailinglist.nvidia";
	stop;
}
# rule:[mailinglist/osi]
if header :contains "from" "do-not-reply@opensource.org"
{
	fileinto "mailinglist.osi";
	stop;
}
# rule:[mailinglist/osi/license-review]
if anyof (header :contains "from" "license-review@lists.opensource.org", header :contains "cc" "license-review@lists.opensource.org", header :contains "to" "license-review@lists.opensource.org")
{
	fileinto "mailinglist.osi.license-review";
	stop;
}
# rule:[mailinglist/plasticity]
if header :contains "from" "contact@plasticity.xyz"
{
	fileinto "mailinglist.plasticity";
	stop;
}
# rule:[mailinglist/qiita]
if header :contains "from" "info@qiita.com"
{
	fileinto "mailinglist.qiita";
	stop;
}
# rule:[mailinglist/qt]
if header :contains "from" "japan@qt.io"
{
	fileinto "mailinglist.qt";
	stop;
}
# rule:[mailinglist/shapr3d]
if header :contains "from" "@shapr3d.com"
{
	fileinto "mailinglist.shapr3d";
	stop;
}
# rule:[mailinglist/ted]
if header :contains "from" "recommends@ted.com"
{
	fileinto "mailinglist.ted";
	stop;
}
# rule:[mailinglist/tor]
if anyof (header :contains "from" "newsletter@torproject.org", header :contains "from" "smith@torproject.org")
{
	fileinto "mailinglist.tor";
	stop;
}
# rule:[mailinglist/tryhackme]
if header :contains "from" "donotreply@tryhackme.com"
{
	fileinto "mailinglist.tryhackme";
	stop;
}
# rule:[mailinglist/twitch]
if header :contains "from" "no-reply@twitch.tv"
{
	setflag "\\Seen";
	fileinto "mailinglist.twitch";
	stop;
}
# rule:[mailinglist/vercel]
if header :contains "from" "ship@info.vercel.com"
{
	fileinto "mailinglist.vercel";
	stop;
}
# rule:[mailinglist/wordpress]
if header :contains "from" "developers@wordpress.com"
{
	fileinto "mailinglist.wordpress";
	stop;
}
# rule:[mailinglist/zed]
if header :contains "from" "zed@mail.zed.dev"
{
	fileinto "mailinglist.zed";
	stop;
}
# rule:[mailinglist/zenn]
if header :contains "from" "noreply@zenn.dev"
{
	fileinto "mailinglist.zenn";
	stop;
}
# rule:[incident/claude]
if header :contains "subject" "Claude Incident -"
{
	fileinto "incident.claude";
	stop;
}
# rule:[incident/github]
if anyof (header :contains "subject" "GitHub Incident -", header :contains "from" "noreply@githubstatus.com")
{
	fileinto "incident.github";
	stop;
}
# rule:[incident]
if header :contains "subject" "Incident"
{
	fileinto "incident";
	stop;
}
# rule:[verification/claude]
if anyof (header :contains "from" "@mail.anthropic.com", header :contains "subject" "Claude.ai")
{
	fileinto "verification.claude";
	stop;
}
# rule:[verification/docker]
if header :contains "from" "@notify.docker.com"
{
	fileinto "verification.docker";
	stop;
}
# rule:[verification/github]
if header :contains "from" "noreply@github.com"
{
	fileinto "verification.github";
	stop;
}
# rule:[verification/google]
if anyof (header :contains "from" "@google.com", header :contains "from" "@accounts.google.com")
{
	fileinto "verification.google";
	stop;
}
# rule:[verification/microsoft]
if header :contains "from" "microsoft.com"
{
	fileinto "verification.microsoft";
	stop;
}
# rule:[verification/mozilla]
if header :contains "from" "accounts@firefox.com"
{
	fileinto "verification.mozilla";
	stop;
}
# rule:[verification/steam]
if header :contains "from" "@steampowered.com"
{
	fileinto "verification.steam";
	stop;
}
# rule:[verification]
if anyof (header :contains "subject" "認証", header :contains "subject" "検証", header :contains "subject" "確認", header :contains "subject" "サインイン", header :contains "subject" "ログイン", header :contains "subject" "ワンタイムコード", header :contains "subject" "ワンタイムパスコード", header :contains "subject" "一時使用コード", header :contains "subject" "verification", header :contains "subject" "confirm", header :contains "subject" "sign in", header :contains "subject" "sign-in", header :contains "subject" "log in", header :contains "subject" "log-in", header :contains "subject" "one time code", header :contains "subject" "one time passcode")
{
	fileinto "verification";
	stop;
}
# rule:[reports]
if anyof (header :contains "to" "dmarc-reports@nercone.dev", header :contains "to" "tls-reports@nercone.dev")
{
	fileinto "reports";
	stop;
}
# rule:[rspamd-spam]
if allof (header :contains "x-spam" "Yes", not header :contains "subject" "t3tra", not header :contains "from" "t3tra", not header :contains "to" "t3tra", not header :contains "cc" "t3tra", not body :text :contains "t3tra")
{
	fileinto "Junk";
	stop;
}
# rule:[mention/nickname]
if anyof (body :text :contains "Nercone", body :text :contains "Nenaicone", body :text :contains "DiamondGotCat")
{
	fileinto :copy "mention.nickname";
}
