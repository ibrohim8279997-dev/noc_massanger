package noc.app.ui

import android.Manifest
import android.media.MediaPlayer
import android.media.MediaRecorder
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.clickable
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import noc.app.MainActivity
import noc.app.R
import noc.app.core.InviteResult
import noc.app.data.Msg
import noc.crypto.Invite
import java.io.File
import java.text.DateFormat
import java.util.Date

private fun errText(e: String?) = e

@Composable fun LockScreen(a: MainActivity) = Page(stringResource(R.string.unlock_title)) {
    Text(stringResource(R.string.unlock_text)); Spacer(Modifier.height(16.dp))
    Button(onClick = { a.unlockWithAuth() }) { Text(stringResource(R.string.unlock_button)) }
    a.ui.error?.let { Spacer(Modifier.height(12.dp)); Text(it, color = MaterialTheme.colorScheme.error) }
}

@Composable fun ProblemScreen(key: String) = Page(stringResource(R.string.problem_title)) {
    Text(stringResource(when (key) {
        "debuggable" -> R.string.problem_debuggable; "debugger" -> R.string.problem_debugger
        "root" -> R.string.problem_root; else -> R.string.problem_signature }))
}

@Composable fun SetupScreen(a: MainActivity) {
    var url by remember { mutableStateOf("http://") }; var token by remember { mutableStateOf("") }; var invite by remember { mutableStateOf<String?>(null) }
    Page(stringResource(R.string.setup_title)) { Scrolling {
        OutlinedTextField(url, { url = it }, label = { Text(stringResource(R.string.setup_url)) }, singleLine = true, modifier = Modifier.fillMaxWidth())
        OutlinedTextField(token, { token = it.trim() }, label = { Text(stringResource(R.string.setup_token)) }, singleLine = true, modifier = Modifier.fillMaxWidth())
        Text(stringResource(R.string.setup_http_note), style = MaterialTheme.typography.bodySmall)
        Button(onClick = { a.connectServer(url.trim(), token) { invite = it } }) { Text(stringResource(R.string.setup_continue)) }
        invite?.let { Text(stringResource(R.string.setup_waiting)); QrImage(it) }
        a.ui.error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
    } }
}

@Composable fun ChatsScreen(a: MainActivity) {
    val db = a.app.db ?: return
    val contacts = remember(a.ui.tick) { db.contacts() }
    Page(stringResource(R.string.chats_title), actions = {
        TextButton(onClick = { a.ui.screen = Screen.Meet }) { Text(stringResource(R.string.add_contact)) }
        TextButton(onClick = { a.ui.screen = Screen.Settings }) { Text(stringResource(R.string.settings)) }
    }) {
        if (contacts.isEmpty()) Text(stringResource(R.string.chats_empty))
        LazyColumn { items(contacts) { c ->
            Text(c.name, style = MaterialTheme.typography.titleMedium, modifier = Modifier.fillMaxWidth().clickable { a.ui.screen = Screen.Chat(c.id) }.padding(vertical = 16.dp))
            HorizontalDivider()
        } }
        a.ui.error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
    }
}

@Composable fun ChatScreen(a: MainActivity, id: Long) {
    val db = a.app.db ?: return
    val contact = remember(id) { db.contact(id) } ?: return
    val msgs by produceState(emptyList<Msg>(), a.ui.tick, id) { value = db.messages(id) }
    var text by remember { mutableStateOf("") }
    var recorder by remember { mutableStateOf<Pair<MediaRecorder, File>?>(null) }
    val ctx = androidx.compose.ui.platform.LocalContext.current
    val picker = rememberLauncherForActivityResult(ActivityResultContracts.GetContent()) { uri ->
        if (uri != null) a.sendPicked(contact, uri)
    }
    val saveName = remember { mutableStateOf<Pair<Long, String>?>(null) }
    val saver = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")) { uri ->
        val s = saveName.value; if (uri != null && s != null) a.saveFile(s.first, uri)
    }
    val mic = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { ok ->
        if (ok) recorder = startRecording(ctx)
    }
    Page(contact.name, onBack = { a.ui.screen = Screen.Chats }, actions = {
        TextButton(onClick = { a.ui.screen = Screen.Safety(id) }) { Text(stringResource(R.string.safety_number)) }
    }) {
        LazyColumn(Modifier.weight(1f), reverseLayout = false) { items(msgs) { m ->
            MessageRow(m, onSave = { saveName.value = m.id to (m.fileName ?: "file"); saver.launch(m.fileName ?: "file") }, onPlay = { a.playVoice(m.id) })
        } }
        a.ui.error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
        Row(verticalAlignment = androidx.compose.ui.Alignment.CenterVertically) {
            OutlinedTextField(text, { text = it }, Modifier.weight(1f), placeholder = { Text(stringResource(R.string.chat_hint)) })
            TextButton(onClick = { picker.launch("*/*") }) { Text(stringResource(R.string.attach)) }
            TextButton(onClick = {
                val r = recorder
                if (r == null) mic.launch(Manifest.permission.RECORD_AUDIO)
                else { recorder = null; a.sendRecording(contact, r.first, r.second) }
            }) { Text(stringResource(if (recorder == null) R.string.record else R.string.stop)) }
            Button(onClick = { if (text.isNotBlank()) { a.sendText(contact, text); text = "" } }) { Text(stringResource(R.string.send)) }
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

@Composable private fun MessageRow(m: Msg, onSave: () -> Unit, onPlay: () -> Unit) {
    val time = remember(m.ts) { DateFormat.getTimeInstance(DateFormat.SHORT).format(Date(m.ts)) }
    Column(Modifier.fillMaxWidth().padding(vertical = 4.dp), horizontalAlignment = if (m.outgoing) androidx.compose.ui.Alignment.End else androidx.compose.ui.Alignment.Start) {
        Surface(color = if (m.outgoing) MaterialTheme.colorScheme.primaryContainer else MaterialTheme.colorScheme.surfaceVariant, shape = MaterialTheme.shapes.medium) {
            Column(Modifier.padding(10.dp)) {
                if (m.text != null) Text(m.text)
                else Row(verticalAlignment = androidx.compose.ui.Alignment.CenterVertically) {
                    Text(m.fileName ?: "", Modifier.weight(1f, fill = false))
                    if (m.voice) TextButton(onClick = onPlay) { Text(stringResource(R.string.play)) }
                    TextButton(onClick = onSave) { Text(stringResource(R.string.save)) }
                }
                Text(time, style = MaterialTheme.typography.labelSmall)
            }
        }
    }
}

@Composable fun SafetyScreen(a: MainActivity, id: Long) {
    val c = a.app.db?.contact(id) ?: return
    val number = remember(id) { a.app.messenger?.safetyNumber(c) ?: "" }
    Page(stringResource(R.string.safety_number), onBack = { a.ui.screen = Screen.Chat(id) }) { Scrolling {
        Text(number.chunked(5).joinToString("  "), style = MaterialTheme.typography.headlineSmall)
        Text(stringResource(R.string.safety_hint))
    } }
}

@Composable fun MeetScreen(a: MainActivity) {
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
    Page(stringResource(R.string.meet_title), onBack = { a.ui.screen = Screen.Chats }) { Scrolling {
        OutlinedTextField(name, { name = it }, label = { Text(stringResource(R.string.meet_name)) }, singleLine = true, modifier = Modifier.fillMaxWidth())
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(onClick = { a.io { shown = a.app.messenger!!.myInvite(); hint = R.string.meet_first } }) { Text(stringResource(R.string.meet_show)) }
            Button(onClick = { scan.launch(ScanOptions().setOrientationLocked(false).setBeepEnabled(false)) }) { Text(stringResource(R.string.meet_scan)) }
        }
        shown?.let { Text(stringResource(hint)); QrImage(it) }
        message?.let { Text(stringResource(it)) }
    } }
    pending?.let { t -> AlertDialog(onDismissRequest = { pending = null },
        title = { Text(stringResource(R.string.key_changed_title)) },
        text = { Text(stringResource(R.string.key_changed_text, runCatching { Invite.decode(t, System.currentTimeMillis() / 1000).deviceKey.take(4).joinToString("") { "%02x".format(it) } }.getOrDefault("?"))) },
        confirmButton = { TextButton(onClick = { pending = null; a.io { a.app.messenger!!.acceptInvite(t, name, confirmChange = true); a.ui.tick++ }; message = R.string.meet_done }) { Text(stringResource(R.string.accept)) } },
        dismissButton = { TextButton(onClick = { pending = null }) { Text(stringResource(R.string.cancel)) } }) }
}

@Composable fun SettingsScreen(a: MainActivity) {
    val db = a.app.db ?: return
    var wipe by remember { mutableStateOf(false) }
    var auto by remember { mutableStateOf(db.setting("autodelete_s", "0")) }
    var cover by remember { mutableStateOf(db.setting("cover", "normal")) }
    var theme by remember { mutableStateOf(a.uiPref("theme", "system")) }
    var lang by remember { mutableStateOf(a.uiPref("lang", "system")) }
    var lockS by remember { mutableStateOf(a.uiPref("lock_s", "30")) }
    @Composable fun choices(title: Int, options: List<Pair<String, Int>>, cur: String, set: (String) -> Unit) {
        Text(stringResource(title), style = MaterialTheme.typography.titleSmall)
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(4.dp)) {
            options.forEach { (v, label) -> FilterChip(cur == v, { set(v) }, { Text(stringResource(label), maxLines = 1) }) } }
    }
    Page(stringResource(R.string.settings), onBack = { a.ui.screen = Screen.Chats }, actions = {
        if (a.app.vault.has("admin")) TextButton(onClick = { a.ui.screen = Screen.Admin }) { Text(stringResource(R.string.admin)) } }) { Scrolling {
        choices(R.string.settings_theme, listOf("system" to R.string.theme_system, "light" to R.string.theme_light, "dark" to R.string.theme_dark), theme) { theme = it; a.setTheme(it) }
        choices(R.string.settings_language, listOf("system" to R.string.lang_system, "ru" to R.string.lang_ru, "en" to R.string.lang_en), lang) { lang = it; a.setLanguage(it) }
        choices(R.string.settings_cover, listOf("normal" to R.string.cover_normal, "paranoid" to R.string.cover_paranoid), cover) { cover = it; db.setSetting("cover", it) }
        Text(stringResource(R.string.cover_note), style = MaterialTheme.typography.bodySmall)
        choices(R.string.settings_autodelete, listOf("0" to R.string.dur_off, "60" to R.string.dur_1m, "3600" to R.string.dur_1h, "86400" to R.string.dur_1d, "604800" to R.string.dur_1w), auto) { auto = it; db.setSetting("autodelete_s", it) }
        choices(R.string.settings_autolock, listOf("30" to R.string.dur_30s, "60" to R.string.dur_1m, "300" to R.string.dur_5m), lockS) { lockS = it; a.setUiPref("lock_s", it) }
        OutlinedButton(onClick = { wipe = true }) { Text(stringResource(R.string.settings_wipe)) }
    } }
    if (wipe) AlertDialog(onDismissRequest = { wipe = false }, text = { Text(stringResource(R.string.wipe_confirm)) },
        confirmButton = { TextButton(onClick = { wipe = false; a.wipe() }) { Text(stringResource(R.string.delete)) } },
        dismissButton = { TextButton(onClick = { wipe = false }) { Text(stringResource(R.string.cancel)) } })
}

@Composable fun AdminScreen(a: MainActivity) {
    var users by remember { mutableStateOf<List<Pair<ByteArray, String>>>(emptyList()) }
    var info by remember { mutableStateOf<Int?>(null) }
    fun reload() = a.withAdmin { s -> users = a.app.messenger!!.api.listUsers(s) }
    val scan = rememberLauncherForActivityResult(ScanContract()) { r ->
        val t = r.contents ?: return@rememberLauncherForActivityResult
        val key = runCatching { Invite.decode(t, System.currentTimeMillis() / 1000).deviceKey }.getOrNull() ?: run { info = R.string.meet_bad; return@rememberLauncherForActivityResult }
        a.withAdmin { s -> a.app.messenger!!.api.addUser(s, key); info = R.string.admin_added; users = a.app.messenger!!.api.listUsers(s) }
    }
    LaunchedEffect(Unit) { reload() }
    Page(stringResource(R.string.admin_title), onBack = { a.ui.screen = Screen.Settings }) { Scrolling {
        Button(onClick = { scan.launch(ScanOptions().setBeepEnabled(false)) }) { Text(stringResource(R.string.admin_add)) }
        info?.let { Text(stringResource(it)) }
        Text(stringResource(R.string.admin_users), style = MaterialTheme.typography.titleSmall)
        users.forEach { (k, role) ->
            Row(verticalAlignment = androidx.compose.ui.Alignment.CenterVertically) {
                Text(k.take(6).joinToString("") { "%02x".format(it) } + "…  " + stringResource(if (role == "superadmin") R.string.admin_role_admin else R.string.admin_role_user), Modifier.weight(1f))
                if (role != "superadmin") TextButton(onClick = { a.withAdmin { s -> a.app.messenger!!.api.removeUser(s, k); users = a.app.messenger!!.api.listUsers(s) } }) { Text(stringResource(R.string.admin_remove)) }
            }
        }
        a.ui.error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
    } }
}
