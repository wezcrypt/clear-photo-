import { useT } from '../lib/i18n';

const EN = (
  <>
    <p>VoidMail uses three different protections. We never call one by another's name.</p>
    <table>
      <thead><tr><th>Protection</th><th>What it means</th><th>Who can read the content</th></tr></thead>
      <tbody>
        <tr><td><b>Transport encryption (TLS)</b></td><td>Encrypted while travelling between two machines.</td><td>Both ends of each hop, including VoidMail and the recipient’s provider.</td></tr>
        <tr><td><b>Encrypted at rest (server-side)</b></td><td>Stored encrypted, but a server handled the plaintext at some point.</td><td>The server while processing it.</td></tr>
        <tr><td><b>End-to-end encryption</b></td><td>Encrypted in the sender’s browser for the recipients’ keys.</td><td>Sender and recipients only (see the limit below).</td></tr>
      </tbody>
    </table>
    <h2>What VoidMail cannot read</h2>
    <p>Subjects, bodies and attachments of messages between VoidMail users; your drafts; your contact-key pins. They are stored only as ciphertext. Your password never leaves your device, and your private keys are uploaded only encrypted with a key derived from it.</p>
    <h2>What VoidMail can see</h2>
    <p>Who you exchange mail with, when, message sizes, folders, read/star flags and label names. For mail to and from other providers: its full content at the moment it arrives or leaves, because standard email requires it. Arriving mail is then encrypted to your key.</p>
    <h2>The limit of browser encryption</h2>
    <p>Encryption runs in code delivered by VoidMail’s server. If that server were compromised or coerced, it could deliver modified code that captures your password the next time you unlock. End-to-end encryption protects against database and backup theft, curious insiders and later compromise — not against a server that actively attacks you. There is currently no independent way for you to verify the code you run.</p>
    <h2>Keys and verification</h2>
    <p>VoidMail’s key directory could, in theory, hand you a fake key for a contact. Keys are pinned the first time you use them and you are warned if one changes. Only keys whose fingerprint you compared with the person through another channel (then “Mark verified”) are protected against substitution at first contact.</p>
    <h2>Recovery</h2>
    <p>Your recovery key resets your password and keeps your mail readable. Resetting by email restores the account but <b>not</b> existing encrypted mail. Without either, nobody — including VoidMail — can recover your mail.</p>
    <h2>Beyond our control</h2>
    <p>A compromised device can read everything you can. Recipients can forward, screenshot or leak what you send. Deletion cannot recall copies already delivered or downloaded.</p>
  </>
);

const AR = (
  <>
    <p>يستخدم VoidMail ثلاث حمايات مختلفة، ولا نسمّي إحداها باسم الأخرى.</p>
    <table>
      <thead><tr><th>الحماية</th><th>معناها</th><th>من يستطيع قراءة المحتوى</th></tr></thead>
      <tbody>
        <tr><td><b>تشفير النقل (TLS)</b></td><td>مشفّر أثناء الانتقال بين جهازين.</td><td>طرفا كل مرحلة، بما في ذلك VoidMail ومزوّد المستلم.</td></tr>
        <tr><td><b>التشفير أثناء التخزين (من جهة الخادم)</b></td><td>يُخزّن مشفّرًا، لكن خادمًا تعامل مع النص الأصلي في لحظة ما.</td><td>الخادم أثناء المعالجة.</td></tr>
        <tr><td><b>التشفير من طرف إلى طرف</b></td><td>يُشفّر في متصفح المرسل لمفاتيح المستلمين.</td><td>المرسل والمستلمون فقط (مع الحدّ المذكور أدناه).</td></tr>
      </tbody>
    </table>
    <h2>ما لا يستطيع VoidMail قراءته</h2>
    <p>مواضيع ومحتوى ومرفقات الرسائل بين مستخدمي VoidMail، ومسوداتك، ومفاتيح جهات الاتصال المثبّتة. تُخزّن كنص مشفّر فقط. كلمة مرورك لا تغادر جهازك، ومفاتيحك الخاصة لا تُرفع إلا مشفّرة بمفتاح مشتق منها.</p>
    <h2>ما يستطيع VoidMail رؤيته</h2>
    <p>مع من تتراسل ومتى، وأحجام الرسائل، والمجلدات، وحالة القراءة والنجمة، وأسماء التصنيفات. وبالنسبة للبريد من وإلى مزوّدين آخرين: محتواه الكامل لحظة وصوله أو إرساله لأن البريد العادي يتطلب ذلك، ثم يُشفّر البريد الوارد بمفتاحك.</p>
    <h2>حدود التشفير داخل المتصفح</h2>
    <p>يعمل التشفير بشيفرة يقدّمها خادم VoidMail. إذا اختُرق الخادم أو أُجبر، يمكنه تقديم شيفرة معدّلة تلتقط كلمة مرورك عند الفتح التالي. يحمي التشفير من طرف إلى طرف من سرقة قاعدة البيانات والنسخ الاحتياطية والمطّلعين الفضوليين والاختراق اللاحق — لكنه لا يحمي من خادم يهاجمك بشكل نشط. لا توجد حاليًا طريقة مستقلة للتحقق من الشيفرة التي تشغّلها.</p>
    <h2>المفاتيح والتحقق</h2>
    <p>يمكن نظريًا لدليل مفاتيح VoidMail أن يقدّم مفتاحًا مزيّفًا لجهة اتصال. تُثبّت المفاتيح عند أول استخدام وتُحذّر إذا تغيّر أحدها. فقط المفاتيح التي قارنت بصمتها مع الشخص عبر قناة أخرى (ثم «تعليم كموثّق») محمية من الاستبدال عند أول تواصل.</p>
    <h2>الاسترداد</h2>
    <p>مفتاح الاسترداد يعيد تعيين كلمة المرور ويُبقي بريدك مقروءًا. إعادة التعيين عبر البريد تعيد الحساب لكن <b>لا</b> تعيد البريد المشفّر الحالي. بدون أيّ منهما لا يستطيع أحد — بما في ذلك VoidMail — استعادة بريدك.</p>
    <h2>خارج سيطرتنا</h2>
    <p>الجهاز المخترق يستطيع قراءة كل ما تقرأه. يمكن للمستلمين إعادة توجيه ما ترسله أو تصويره أو تسريبه. الحذف لا يستعيد النسخ التي سُلّمت أو نُزّلت.</p>
  </>
);

export function SecurityInfo() {
  const { t, locale } = useT();
  return (
    <div className="settings-inner prose">
      <h1>{t('secTitle')}</h1>
      {locale === 'ar' ? AR : EN}
    </div>
  );
}
