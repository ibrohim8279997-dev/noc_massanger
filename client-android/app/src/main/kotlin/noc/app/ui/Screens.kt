package noc.app.ui

import android.Manifest
import android.media.MediaRecorder
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import noc.app.BuildConfig
import noc.app.MainActivity
import noc.app.R
import noc.client.InviteResult
import noc.client.Msg
import noc.crypto.Invite
import java.io.File
import java.text.DateFormat
import java.util.Date

private fun hex(b: ByteArray, n: Int) = b.take(n).joinToString("") { "%02x".format(it) }
private fun clock(ts: Long): String = DateFormat.getTimeInstance(DateFormat.SHORT).format(Date(ts))

@Composable private fun ErrorLine(a: MainActivity) {
    val pal = LocalPal.current
    a.ui.error?.let { Text(it, color = pal.bad, fontSize = 13.sp, modifier = Modifier.padding(vertical = 6.dp)) }
}

// ============================================================ lock / problem / setup
@Composable fun LockScreen(a: MainActivity) {
    val pal = LocalPal.current
    Column(Modifier.fillMaxSize().systemBarsPadding().padding(28.dp), horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.Center) {
        Logo(96); Spacer(Modifier.height(18.dp))
        Text("NOCTRA", color = pal.text, fontSize = 34.sp, fontWeight = FontWeight.Light, letterSpacing = 4.sp)
        Text(stringResource(R.string.tagline), color = pal.sub, fontSize = 15.sp)
        Spacer(Modifier.height(36.dp))
        Text(stringResource(R.string.unlock_text), color = pal.sub, textAlign = TextAlign.Center); Spacer(Modifier.height(16.dp))
        PrimaryButton(stringResource(R.string.unlock_button), { a.unlockWithAuth() })
        ErrorLine(a)
    }
}

@Composable fun ProblemScreen(key: String) = Page(stringResource(R.string.problem_title)) {
    Text(stringResource(when (key) {
        "debuggable" -> R.string.problem_debuggable; "debugger" -> R.string.problem_debugger
        "root" -> R.string.problem_root; else -> R.string.problem_signature }), color = LocalPal.current.text)
}

@Composable fun SetupScreen(a: MainActivity) {
    val pal = LocalPal.current
    var url by remember { mutableStateOf("http://") }; var token by remember { mutableStateOf("") }; var card by remember { mutableStateOf<String?>(null) }
    Page(stringResource(R.string.setup_title)) { Scrolling {
        Field(url, { url = it }, stringResource(R.string.setup_url))
        Field(token, { token = it.trim() }, stringResource(R.string.setup_token))
        Text(stringResource(R.string.setup_http_note), color = pal.sub, fontSize = 12.sp)
        PrimaryButton(stringResource(R.string.setup_continue), { a.connectServer(url.trim(), token) { card = it } })
        card?.let { Card { Text(stringResource(R.string.setup_waiting), color = pal.text); Spacer(Modifier.height(12.dp)); QrImage(it) } }
        ErrorLine(a)
    } }
}

@Composable fun Field(value: String, onChange: (String) -> Unit, label: String, modifier: Modifier = Modifier) {
    val pal = LocalPal.current
    OutlinedTextField(value, onChange, modifier.fillMaxWidth(), label = { Text(label) }, singleLine = true, shape = RoundedCornerShape(14.dp),
        colors = OutlinedTextFieldDefaults.colors(focusedBorderColor = pal.accent, unfocusedBorderColor = pal.line, focusedTextColor = pal.text, unfocusedTextColor = pal.text,
            focusedContainerColor = pal.surface, unfocusedContainerColor = pal.surface))
}

// ============================================================ chats
@Composable fun ChatsScreen(a: MainActivity) {
    val db = a.app.db ?: return
    val pal = LocalPal.current
    var query by remember { mutableStateOf("") }; var onlyUnread by remember { mutableStateOf(false) }
    class Row(val id: Long, val name: String, val last: noc.client.LastMsg?, val unread: Int)
    val rows = remember(a.ui.tick) {
        db.contacts().map { Row(it.id, it.name, db.lastMessage(it.id), db.unreadCount(it.id, db.setting("read_${it.id}", "0").toLong())) } +
        db.groups().map { Row(-it.id, it.name, db.lastMessage(-it.id), db.unreadCount(-it.id, db.setting("read_${-it.id}", "0").toLong())) }
    }
    val totalUnread = rows.sumOf { it.unread }
    val shown = rows.filter { (query.isBlank() || it.name.contains(query, true)) && (!onlyUnread || it.unread > 0) }.sortedByDescending { it.last?.ts ?: 0 }
    Tabbed(Screen.Chats, { a.ui.screen = it }) {
        Column(Modifier.systemBarsPadding().padding(horizontal = 16.dp).weight(1f)) {
            Row(Modifier.fillMaxWidth().height(56.dp), verticalAlignment = Alignment.CenterVertically) {
                Text("NOCTRA", color = pal.text, fontSize = 22.sp, fontWeight = FontWeight.Medium, letterSpacing = 2.sp, modifier = Modifier.weight(1f))
                Ico(Ic.Shield, pal.accent, 26, Modifier.clickableNoRipple { a.ui.screen = Screen.Protect })
            }
            a.ui.torText?.let { Text(it, color = pal.sub, fontSize = 12.sp, modifier = Modifier.padding(bottom = 6.dp)) }
            SearchBox(query) { query = it }
            Spacer(Modifier.height(10.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Pill(stringResource(R.string.filter_all), !onlyUnread) { onlyUnread = false }
                Pill(stringResource(R.string.filter_unread) + if (totalUnread > 0) "  $totalUnread" else "", onlyUnread) { onlyUnread = true }
            }
            if (!a.ui.registered) {
                Spacer(Modifier.height(10.dp))
                Card { Text(stringResource(R.string.not_registered_title), color = pal.bad, fontWeight = FontWeight.SemiBold)
                    Text(stringResource(R.string.setup_waiting), color = pal.sub, fontSize = 13.sp)
                    Spacer(Modifier.height(10.dp)); a.app.messenger?.let { QrImage(remember { it.deviceCard() }) } }
            }
            if (rows.isEmpty()) Text(stringResource(R.string.chats_empty), color = pal.sub, modifier = Modifier.padding(top = 24.dp))
            LazyColumn(Modifier.weight(1f).padding(top = 8.dp)) { items(shown) { r ->
                Row(Modifier.fillMaxWidth().clickableNoRipple { a.ui.screen = Screen.Chat(r.id) }.padding(vertical = 10.dp), verticalAlignment = Alignment.CenterVertically) {
                    Avatar(r.name, 52); Spacer(Modifier.width(12.dp))
                    Column(Modifier.weight(1f)) {
                        Text(r.name, color = pal.text, fontSize = 16.sp, fontWeight = FontWeight.SemiBold, maxLines = 1)
                        val l = r.last; val lt = l?.text; val vm = stringResource(R.string.voice_message); val fl = stringResource(R.string.file_label)
                        Text(when { l == null -> ""; lt != null -> lt; l.voice -> vm; else -> l.fileName ?: fl },
                            color = pal.sub, fontSize = 14.sp, maxLines = 1)
                    }
                    Column(horizontalAlignment = Alignment.End) {
                        r.last?.let { Text(clock(it.ts), color = pal.sub, fontSize = 12.sp) }
                        if (r.unread > 0) Box(Modifier.padding(top = 4.dp).size(22.dp).clip(CircleShape).background(pal.accent), contentAlignment = Alignment.Center) {
                            Text("${r.unread}", color = Color.White, fontSize = 12.sp) }
                    }
                }
                HorizontalDivider(color = pal.line.copy(alpha = 0.5f))
            } }
            ErrorLine(a)
        }
    }
}

@Composable private fun SearchBox(value: String, onChange: (String) -> Unit) {
    val pal = LocalPal.current
    Row(Modifier.fillMaxWidth().height(46.dp).clip(RoundedCornerShape(14.dp)).background(pal.surface).padding(horizontal = 14.dp), verticalAlignment = Alignment.CenterVertically) {
        Ico(Ic.Search, pal.sub, 20); Spacer(Modifier.width(10.dp))
        Box(Modifier.weight(1f)) {
            if (value.isEmpty()) Text(stringResource(R.string.search), color = pal.sub)
            BasicTextField(value, onChange, singleLine = true, textStyle = TextStyle(color = pal.text, fontSize = 16.sp), cursorBrush = SolidColor(pal.accent), modifier = Modifier.fillMaxWidth())
        }
    }
}

// ============================================================ contacts
@Composable fun ContactsScreen(a: MainActivity) {
    val db = a.app.db ?: return
    val pal = LocalPal.current
    val contacts = remember(a.ui.tick) { db.contacts() }
    Tabbed(Screen.Contacts, { a.ui.screen = it }) {
        Column(Modifier.systemBarsPadding().padding(horizontal = 16.dp).weight(1f)) {
            Row(Modifier.fillMaxWidth().height(56.dp), verticalAlignment = Alignment.CenterVertically) {
                Text(stringResource(R.string.nav_contacts), color = pal.text, fontSize = 22.sp, fontWeight = FontWeight.SemiBold) }
            PrimaryButton(stringResource(R.string.add_contact), { a.ui.screen = Screen.Meet })
            if (contacts.isNotEmpty()) { Spacer(Modifier.height(8.dp)); SecondaryButton(stringResource(R.string.group_new), { a.ui.screen = Screen.GroupNew }) }
            if (a.app.vault.has("admin")) { Spacer(Modifier.height(8.dp)); SecondaryButton(stringResource(R.string.add_user), { a.ui.screen = Screen.Admin }) }
            Spacer(Modifier.height(8.dp))
            if (contacts.isEmpty()) Text(stringResource(R.string.chats_empty), color = pal.sub, modifier = Modifier.padding(top = 16.dp))
            LazyColumn { items(contacts) { c ->
                Row(Modifier.fillMaxWidth().clickableNoRipple { a.ui.screen = Screen.Chat(c.id) }.padding(vertical = 10.dp), verticalAlignment = Alignment.CenterVertically) {
                    Avatar(c.name, 44); Spacer(Modifier.width(12.dp))
                    Text(c.name, color = pal.text, fontSize = 16.sp, modifier = Modifier.weight(1f))
                    Ico(Ic.Chevron, pal.sub)
                }
                HorizontalDivider(color = pal.line.copy(alpha = 0.5f))
            } }
        }
    }
}

// ============================================================ chat
@Composable fun ChatScreen(a: MainActivity, id: Long) {
    val db = a.app.db ?: return
    val pal = LocalPal.current
    val contact = remember(id) { if (id > 0) db.contact(id) else null }
    val group = remember(id) { if (id < 0) db.group(-id) else null }
    if (contact == null && group == null) return
    val title = contact?.name ?: group!!.name
    val names = remember(a.ui.tick) { db.contacts().associate { it.id to it.name } }
    val msgs by produceState(emptyList<Msg>(), a.ui.tick, id) { value = db.messages(id) }
    LaunchedEffect(id, a.ui.tick) { db.setSetting("read_$id", System.currentTimeMillis().toString()) }
    var text by remember { mutableStateOf("") }
    var recorder by remember { mutableStateOf<Pair<MediaRecorder, File>?>(null) }
    val ctx = androidx.compose.ui.platform.LocalContext.current
    val picker = rememberLauncherForActivityResult(ActivityResultContracts.GetContent()) { uri -> if (uri != null && contact != null) a.sendPicked(contact, uri) }
    val saveName = remember { mutableStateOf<Long?>(null) }
    val saver = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")) { uri -> val s = saveName.value; if (uri != null && s != null) a.saveFile(s, uri) }
    val mic = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { ok -> if (ok) recorder = startRecording(ctx) }
    val listState = androidx.compose.foundation.lazy.rememberLazyListState()
    LaunchedEffect(msgs.size) { if (msgs.isNotEmpty()) listState.animateScrollToItem(msgs.size - 1) }

    Column(Modifier.fillMaxSize().systemBarsPadding().imePadding()) {
        Row(Modifier.fillMaxWidth().padding(horizontal = 12.dp).height(60.dp), verticalAlignment = Alignment.CenterVertically) {
            Box(Modifier.clickableNoRipple { a.ui.screen = Screen.Chats }.padding(end = 10.dp, top = 8.dp, bottom = 8.dp)) { Ico(Ic.Back, pal.text) }
            Avatar(title, 40); Spacer(Modifier.width(10.dp))
            Column(Modifier.weight(1f).clickableNoRipple { if (contact != null) a.ui.screen = Screen.Safety(id) }) {
                Text(title, color = pal.text, fontSize = 17.sp, fontWeight = FontWeight.SemiBold, maxLines = 1)
                if (contact != null) Text(stringResource(R.string.safety_number), color = pal.accent, fontSize = 12.sp)
            }
        }
        Row(Modifier.fillMaxWidth().padding(vertical = 6.dp), horizontalArrangement = Arrangement.Center, verticalAlignment = Alignment.CenterVertically) {
            Ico(Ic.Lock, pal.sub, 14); Spacer(Modifier.width(6.dp)); Text(stringResource(R.string.enc_active), color = pal.sub, fontSize = 12.sp)
        }
        LazyColumn(Modifier.weight(1f).padding(horizontal = 12.dp), state = listState, verticalArrangement = Arrangement.spacedBy(8.dp)) { items(msgs) { m ->
            Bubble(m, sender = if (group != null && !m.outgoing) names[m.senderId] else null, onSave = { saveName.value = m.id; saver.launch(m.fileName ?: "file") }, onPlay = { a.playVoice(m.id) })
        } }
        ErrorLine(a)
        Row(Modifier.fillMaxWidth().padding(10.dp), verticalAlignment = Alignment.CenterVertically) {
            if (contact != null) Box(Modifier.clickableNoRipple { picker.launch("*/*") }.padding(8.dp)) { Ico(Ic.Clip, pal.sub) }
            Box(Modifier.weight(1f).clip(RoundedCornerShape(24.dp)).background(pal.surface).padding(horizontal = 16.dp, vertical = 12.dp)) {
                if (text.isEmpty()) Text(stringResource(R.string.chat_hint), color = pal.sub)
                BasicTextField(text, { text = it }, textStyle = TextStyle(color = pal.text, fontSize = 16.sp), cursorBrush = SolidColor(pal.accent), modifier = Modifier.fillMaxWidth(), maxLines = 5)
            }
            Spacer(Modifier.width(8.dp))
            val rec = recorder != null
            Box(Modifier.size(46.dp).clip(CircleShape).background(if (rec) pal.bad else pal.accent).clickableNoRipple {
                when {
                    text.isNotBlank() -> { if (contact != null) a.sendText(contact, text) else a.sendGroupText(group!!, text); text = "" }
                    contact == null -> {}
                    rec -> { val r = recorder!!; recorder = null; a.sendRecording(contact, r.first, r.second) }
                    else -> mic.launch(Manifest.permission.RECORD_AUDIO)
                }
            }, contentAlignment = Alignment.Center) { Ico(if (text.isNotBlank()) Ic.Send else if (rec) Ic.Stop else Ic.Mic, Color.White, 22) }
        }
    }
}

private fun startRecording(ctx: android.content.Context): Pair<MediaRecorder, File> {
    val f = File.createTempFile("voice", ".m4a", ctx.cacheDir)
    val r = MediaRecorder(ctx).apply {
        setAudioSource(MediaRecorder.AudioSource.MIC); setOutputFormat(MediaRecorder.OutputFormat.MPEG_4)
        setAudioEncoder(MediaRecorder.AudioEncoder.AAC); setOutputFile(f.path); prepare(); start()
    }
    return r to f
}

@Composable private fun Bubble(m: Msg, sender: String?, onSave: () -> Unit, onPlay: () -> Unit) {
    val pal = LocalPal.current
    val outText = if (androidx.compose.foundation.isSystemInDarkTheme()) Color.White else pal.text
    Row(Modifier.fillMaxWidth(), horizontalArrangement = if (m.outgoing) Arrangement.End else Arrangement.Start) {
        Column(Modifier.widthIn(max = 300.dp).clip(RoundedCornerShape(18.dp)).background(if (m.outgoing) pal.out else pal.surface).padding(horizontal = 14.dp, vertical = 10.dp)) {
            if (sender != null) Text(sender, color = pal.accent, fontSize = 12.sp, fontWeight = FontWeight.SemiBold)
            val mt = m.text
            if (mt != null) Text(mt, color = if (m.outgoing) outText else pal.text, fontSize = 16.sp)
            else if (m.voice) Row(verticalAlignment = Alignment.CenterVertically) {
                Box(Modifier.size(38.dp).clip(CircleShape).background(pal.accent).clickableNoRipple(onPlay), contentAlignment = Alignment.Center) { Ico(Ic.Play, Color.White, 22) }
                Spacer(Modifier.width(10.dp)); Waveform(m.id, if (m.outgoing) outText.copy(alpha = 0.8f) else pal.accent)
            } else Row(verticalAlignment = Alignment.CenterVertically) {
                Ico(Ic.Clip, pal.sub, 20); Spacer(Modifier.width(8.dp))
                Text(m.fileName ?: "", color = pal.text, modifier = Modifier.weight(1f, fill = false), maxLines = 2)
            }
            Row(Modifier.align(Alignment.End), verticalAlignment = Alignment.CenterVertically) {
                if (m.hasFile) Text(stringResource(R.string.save), color = pal.accent, fontSize = 12.sp, modifier = Modifier.clickableNoRipple(onSave).padding(end = 10.dp))
                Text(clock(m.ts), color = pal.sub, fontSize = 11.sp)
                if (m.outgoing) { Spacer(Modifier.width(4.dp)); Ico(Ic.Check, pal.accent, 14) }
            }
        }
    }
}

@Composable fun SafetyScreen(a: MainActivity, id: Long) {
    val pal = LocalPal.current
    val c = a.app.db?.contact(id) ?: return
    val number = remember(id) { a.app.messenger?.safetyNumber(c) ?: "" }
    Page(stringResource(R.string.safety_number), onBack = { a.ui.screen = Screen.Chat(id) }) { Scrolling {
        Card { Text(number.chunked(5).joinToString("  "), color = pal.text, fontSize = 22.sp, fontWeight = FontWeight.Medium, lineHeight = 34.sp) }
        Text(stringResource(R.string.safety_hint), color = pal.sub)
    } }
}

// ============================================================ meet in person
@Composable fun MeetScreen(a: MainActivity) {
    val pal = LocalPal.current
    var shown by remember { mutableStateOf<String?>(null) }; var hint by remember { mutableStateOf(R.string.meet_first) }
    var name by remember { mutableStateOf("") }; var message by remember { mutableStateOf<Int?>(null) }
    var pending by remember { mutableStateOf<String?>(null) }
    val scan = rememberLauncherForActivityResult(ScanContract()) { r ->
        val t = r.contents ?: return@rememberLauncherForActivityResult
        a.io {
            when (val res = a.app.messenger!!.acceptInvite(t, name)) {
                is InviteResult.Added -> { message = R.string.meet_done; res.replyInvite?.let { shown = it; hint = R.string.meet_reply } }
                is InviteResult.KeyChanged -> pending = t
                InviteResult.Rejected -> message = R.string.meet_bad
            }
            a.ui.tick++
        }
    }
    Page(stringResource(R.string.meet_title), onBack = { a.ui.screen = Screen.Contacts }) { Scrolling {
        Field(name, { name = it }, stringResource(R.string.meet_name))
        PrimaryButton(stringResource(R.string.meet_show), { a.io { shown = a.app.messenger!!.myInvite(); hint = R.string.meet_first } })
        SecondaryButton(stringResource(R.string.meet_scan), { scan.launch(ScanOptions().setOrientationLocked(false).setBeepEnabled(false)) })
        shown?.let { Text(stringResource(hint), color = pal.sub); QrImage(it) }
        message?.let { Text(stringResource(it), color = pal.text) }
        ErrorLine(a)
    } }
    pending?.let { t -> AlertDialog(onDismissRequest = { pending = null },
        title = { Text(stringResource(R.string.key_changed_title)) },
        text = { Text(stringResource(R.string.key_changed_text, runCatching { hex(Invite.decode(t, System.currentTimeMillis() / 1000).deviceKey, 4) }.getOrDefault("?"))) },
        confirmButton = { TextButton(onClick = { pending = null; a.io { a.app.messenger!!.acceptInvite(t, name, confirmChange = true); a.ui.tick++ }; message = R.string.meet_done }) { Text(stringResource(R.string.accept)) } },
        dismissButton = { TextButton(onClick = { pending = null }) { Text(stringResource(R.string.cancel)) } }) }
}

// ============================================================ protection center (real state, no score)
@Composable fun ProtectScreen(a: MainActivity) {
    val db = a.app.db ?: return
    val pal = LocalPal.current
    val disappearOn = (db.setting("autodelete_s", "0").toIntOrNull() ?: 0) > 0
    val items = listOf(R.string.protect_e2e to true, R.string.protect_disappear to disappearOn, R.string.protect_screens to true, R.string.protect_lock to true,
        R.string.protect_tor to a.app.viaTor, R.string.protect_cover to true)
    val active = items.count { it.second }
    Tabbed(Screen.Protect, { a.ui.screen = it }) {
        Column(Modifier.systemBarsPadding().padding(horizontal = 16.dp).weight(1f)) {
            Row(Modifier.fillMaxWidth().height(56.dp), verticalAlignment = Alignment.CenterVertically) {
                Text(stringResource(R.string.protect_title), color = pal.text, fontSize = 22.sp, fontWeight = FontWeight.SemiBold) }
            Scrolling(Modifier.weight(1f)) {
                Box(Modifier.fillMaxWidth().padding(vertical = 8.dp), contentAlignment = Alignment.Center) {
                    Canvas(Modifier.size(190.dp)) {
                        val sw = 12.dp.toPx(); val d = Size(size.width - sw, size.height - sw)
                        drawArc(pal.line, 0f, 360f, false, androidx.compose.ui.geometry.Offset(sw / 2, sw / 2), d, style = Stroke(sw))
                        drawArc(Brush.sweepGradient(listOf(pal.accent, Color(0xFF7CC4FF), pal.accent)), -90f, 360f * active / items.size, false,
                            androidx.compose.ui.geometry.Offset(sw / 2, sw / 2), d, style = Stroke(sw, cap = StrokeCap.Round))
                    }
                    Column(horizontalAlignment = Alignment.CenterHorizontally) {
                        Ico(Ic.Shield, pal.accent, 34)
                        Text("$active/${items.size}", color = pal.text, fontSize = 38.sp, fontWeight = FontWeight.Light)
                    }
                }
                Text(stringResource(if (active == items.size) R.string.protect_all else R.string.protect_some), color = pal.text, fontSize = 18.sp,
                    fontWeight = FontWeight.SemiBold, textAlign = TextAlign.Center, modifier = Modifier.fillMaxWidth())
                Card { items.forEach { (label, on) ->
                    Row(Modifier.fillMaxWidth().padding(vertical = 10.dp), verticalAlignment = Alignment.CenterVertically) {
                        Ico(when (label) { R.string.protect_disappear -> Ic.Clock; R.string.protect_screens, R.string.protect_tor, R.string.protect_cover -> Ic.Shield; else -> Ic.Lock }, pal.text, 22)
                        Spacer(Modifier.width(12.dp)); Text(stringResource(label), color = pal.text, modifier = Modifier.weight(1f))
                        Box(Modifier.size(22.dp).clip(CircleShape).background(if (on) pal.accent else pal.line), contentAlignment = Alignment.Center) { if (on) Ico(Ic.Check, Color.White, 14) }
                    }
                } }
                Card { Row(verticalAlignment = Alignment.CenterVertically) { Ico(Ic.Shield, pal.accent, 28); Spacer(Modifier.width(12.dp))
                    Text(stringResource(R.string.protect_keys), color = pal.text, fontWeight = FontWeight.SemiBold) } }
                if (!a.app.viaTor) Text(stringResource(R.string.protect_note), color = pal.sub, fontSize = 12.sp)
            }
        }
    }
}

// ============================================================ settings
@OptIn(androidx.compose.foundation.layout.ExperimentalLayoutApi::class)
@Composable fun SettingsScreen(a: MainActivity) {
    val db = a.app.db ?: return
    val pal = LocalPal.current
    var wipe by remember { mutableStateOf(false) }
    var auto by remember { mutableStateOf(db.setting("autodelete_s", "0")) }
    var cover by remember { mutableStateOf(db.setting("cover", "normal")) }
    var theme by remember { mutableStateOf(a.uiPref("theme", "system")) }
    var lang by remember { mutableStateOf(a.uiPref("lang", "system")) }
    var lockS by remember { mutableStateOf(a.uiPref("lock_s", "30")) }
    @Composable fun choices(title: Int, options: List<Pair<String, Int>>, cur: String, set: (String) -> Unit) {
        Text(stringResource(title), color = pal.text, fontWeight = FontWeight.Medium, modifier = Modifier.padding(top = 10.dp, bottom = 6.dp))
        androidx.compose.foundation.layout.FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            options.forEach { (v, label) -> Pill(stringResource(label), cur == v) { set(v) } } }
    }
    @Composable fun section(title: Int) = Text(stringResource(title).uppercase(), color = pal.sub, fontSize = 12.sp, letterSpacing = 1.sp, modifier = Modifier.padding(top = 8.dp))
    Tabbed(Screen.Settings, { a.ui.screen = it }) {
        Column(Modifier.systemBarsPadding().padding(horizontal = 16.dp).weight(1f)) {
            Row(Modifier.fillMaxWidth().height(56.dp), verticalAlignment = Alignment.CenterVertically) {
                Text(stringResource(R.string.nav_settings), color = pal.text, fontSize = 22.sp, fontWeight = FontWeight.SemiBold) }
            Scrolling(Modifier.weight(1f)) {
                Card { Row(verticalAlignment = Alignment.CenterVertically) {
                    val id = a.app.messenger?.signer?.publicKey?.let { hex(it, 4) } ?: "—"
                    Avatar(id, 56); Spacer(Modifier.width(14.dp))
                    Column { Text("Noctra", color = pal.text, fontSize = 18.sp, fontWeight = FontWeight.SemiBold)
                        Text(stringResource(R.string.profile_id) + ": " + id, color = pal.sub, fontSize = 13.sp) } } }
                section(R.string.section_appearance)
                Card {
                    choices(R.string.settings_theme, listOf("system" to R.string.theme_system, "light" to R.string.theme_light, "dark" to R.string.theme_dark), theme) { theme = it; a.setTheme(it) }
                    choices(R.string.settings_language, listOf("system" to R.string.lang_system, "ru" to R.string.lang_ru, "en" to R.string.lang_en), lang) { lang = it; a.setLanguage(it) }
                }
                section(R.string.section_security)
                Card {
                    choices(R.string.settings_autodelete, listOf("0" to R.string.dur_off, "60" to R.string.dur_1m, "3600" to R.string.dur_1h, "86400" to R.string.dur_1d, "604800" to R.string.dur_1w), auto) { auto = it; db.setSetting("autodelete_s", it) }
                    choices(R.string.settings_autolock, listOf("30" to R.string.dur_30s, "60" to R.string.dur_1m, "300" to R.string.dur_5m), lockS) { lockS = it; a.setUiPref("lock_s", it) }
                }
                section(R.string.section_network)
                Card {
                    choices(R.string.settings_cover, listOf("normal" to R.string.cover_normal, "paranoid" to R.string.cover_paranoid), cover) { cover = it; db.setSetting("cover", it) }
                    Text(stringResource(R.string.cover_note), color = pal.sub, fontSize = 12.sp, modifier = Modifier.padding(top = 8.dp))
                    Text(stringResource(if (a.app.viaTor) R.string.net_tor else R.string.net_direct), color = pal.text, modifier = Modifier.padding(top = 12.dp))
                    var server by remember { mutableStateOf(db.setting("server", "")) }; var saved by remember { mutableStateOf(false) }
                    Field(server, { server = it; saved = false }, stringResource(R.string.setup_url), Modifier.padding(top = 8.dp))
                    Spacer(Modifier.height(8.dp))
                    SecondaryButton(stringResource(R.string.server_change), { a.changeServer(server) { saved = true } })
                    if (saved) Text(stringResource(R.string.server_changed), color = pal.ok, fontSize = 13.sp)
                    var bridges by remember { mutableStateOf(db.setting("bridges", "")) }
                    OutlinedTextField(bridges, { bridges = it; db.setSetting("bridges", it) }, Modifier.fillMaxWidth().padding(top = 8.dp),
                        label = { Text(stringResource(R.string.tor_bridges)) }, minLines = 2, shape = RoundedCornerShape(14.dp))
                    Text(stringResource(R.string.tor_bridges_hint), color = pal.sub, fontSize = 12.sp, modifier = Modifier.padding(top = 4.dp))
                    var rotated by remember { mutableStateOf(false) }
                    Spacer(Modifier.height(10.dp))
                    SecondaryButton(stringResource(R.string.rotate_now), { a.rotateNow { rotated = true } })
                    if (rotated) Text(stringResource(R.string.rotate_done), color = pal.ok, fontSize = 13.sp)
                }
                section(R.string.section_mesh)
                Card {
                    var on by remember { mutableStateOf(db.setting("mesh", "off") == "on") }
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(stringResource(R.string.mesh_switch), color = pal.text, modifier = Modifier.weight(1f))
                        Switch(on, { on = it; db.setSetting("mesh", if (it) "on" else "off"); if (it) a.enableMesh() else a.disableMesh() })
                    }
                    Text(stringResource(R.string.mesh_note), color = pal.sub, fontSize = 12.sp, modifier = Modifier.padding(top = 6.dp))
                    if (on) a.mesh?.let { Text(stringResource(R.string.mesh_status, it.neighbours, it.held), color = pal.text, modifier = Modifier.padding(top = 8.dp)) }
                }
                if (a.app.vault.has("admin")) { section(R.string.section_admin); SecondaryButton(stringResource(R.string.admin_open), { a.ui.screen = Screen.Admin }) }
                SecondaryButton(stringResource(R.string.settings_wipe), { wipe = true })
                Text(stringResource(R.string.about) + " · " + stringResource(R.string.version, BuildConfig.VERSION_NAME), color = pal.sub, fontSize = 12.sp, modifier = Modifier.padding(bottom = 12.dp))
            }
        }
    }
    if (wipe) AlertDialog(onDismissRequest = { wipe = false }, text = { Text(stringResource(R.string.wipe_confirm)) },
        confirmButton = { TextButton(onClick = { wipe = false; a.wipe() }) { Text(stringResource(R.string.delete)) } },
        dismissButton = { TextButton(onClick = { wipe = false }) { Text(stringResource(R.string.cancel)) } })
}

// ============================================================ admin
@Composable fun AdminScreen(a: MainActivity) {
    val pal = LocalPal.current
    var users by remember { mutableStateOf<List<Pair<ByteArray, String>>>(emptyList()) }
    var info by remember { mutableStateOf<Int?>(null) }
    val scan = rememberLauncherForActivityResult(ScanContract()) { r ->
        val t = r.contents ?: return@rememberLauncherForActivityResult
        val key = runCatching { Invite.decode(t, System.currentTimeMillis() / 1000).deviceKey }.getOrNull() ?: run { info = R.string.meet_bad; return@rememberLauncherForActivityResult }
        a.withAdmin { s -> a.app.messenger!!.api.addUser(s, key); info = R.string.admin_added; users = a.app.messenger!!.api.listUsers(s) }
    }
    Page(stringResource(R.string.admin_title), onBack = { a.ui.screen = Screen.Contacts }) { Scrolling {
        PrimaryButton(stringResource(R.string.admin_add), { scan.launch(ScanOptions().setOrientationLocked(false).setBeepEnabled(false)) })
        SecondaryButton(stringResource(R.string.admin_users), { a.withAdmin { s -> users = a.app.messenger!!.api.listUsers(s) } })
        SecondaryButton(stringResource(R.string.admin_rotate), { a.withAdmin { old ->
            val seed = noc.crypto.SeedSigner.newSeed(); val fresh = noc.crypto.SeedSigner(seed)
            a.app.messenger!!.api.rotateAdminKey(old, fresh)
            a.app.vault.store("admin", "noc_admin", seed); seed.fill(0); info = R.string.admin_rotated
        } })
        info?.let { Text(stringResource(it), color = pal.ok) }
        users.forEach { (k, role) ->
            Card { Row(verticalAlignment = Alignment.CenterVertically) {
                Avatar(hex(k, 1), 36); Spacer(Modifier.width(10.dp))
                Text(hex(k, 6) + "…  " + stringResource(if (role == "superadmin") R.string.admin_role_admin else R.string.admin_role_user), color = pal.text, modifier = Modifier.weight(1f))
                if (role != "superadmin") TextButton(onClick = { a.withAdmin { s -> a.app.messenger!!.api.removeUser(s, k); users = a.app.messenger!!.api.listUsers(s) } }) { Text(stringResource(R.string.admin_remove), color = pal.bad) }
            } }
        }
        ErrorLine(a)
    } }
}

@Composable fun GroupNewScreen(a: MainActivity) {
    val db = a.app.db ?: return
    val pal = LocalPal.current
    val contacts = remember { db.contacts() }
    var name by remember { mutableStateOf("") }; val picked = remember { mutableStateListOf<Long>() }
    Page(stringResource(R.string.group_new), onBack = { a.ui.screen = Screen.Contacts }) { Scrolling {
        Field(name, { name = it }, stringResource(R.string.group_name))
        Text(stringResource(R.string.group_pick), color = pal.sub)
        contacts.forEach { c ->
            Row(Modifier.fillMaxWidth().clickableNoRipple { if (c.id in picked) picked.remove(c.id) else picked.add(c.id) }.padding(vertical = 8.dp), verticalAlignment = Alignment.CenterVertically) {
                Avatar(c.name, 40); Spacer(Modifier.width(12.dp)); Text(c.name, color = pal.text, modifier = Modifier.weight(1f))
                Box(Modifier.size(24.dp).clip(CircleShape).background(if (c.id in picked) pal.accent else pal.line), contentAlignment = Alignment.Center) { if (c.id in picked) Ico(Ic.Check, Color.White, 16) }
            }
        }
        PrimaryButton(stringResource(R.string.group_create), { if (name.isNotBlank() && picked.isNotEmpty()) a.createGroup(name.trim(), contacts.filter { it.id in picked }) })
        ErrorLine(a)
    } }
}
