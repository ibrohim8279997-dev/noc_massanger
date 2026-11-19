package noc.app.ui

import android.graphics.Bitmap
import android.graphics.Color as AColor
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.graphics.vector.PathParser
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.google.zxing.BarcodeFormat
import com.google.zxing.qrcode.QRCodeWriter

sealed class Screen {
    object Lock : Screen(); class Problem(val key: String) : Screen(); object Setup : Screen()
    object Chats : Screen(); object Contacts : Screen(); object Protect : Screen(); object Settings : Screen()
    class Chat(val id: Long) : Screen(); object Meet : Screen(); object GroupNew : Screen(); object Admin : Screen(); class Safety(val id: Long) : Screen()
}

class UiState {
    var screen by mutableStateOf<Screen>(Screen.Lock)
    var tick by mutableIntStateOf(0)
    var error by mutableStateOf<String?>(null)
    var registered by mutableStateOf(true)
    var torText by mutableStateOf<String?>(null)
}

// ---------------------------------------------------------------- palette (dark navy + blue accent, as in the design)
class Pal(val bg: Color, val surface: Color, val surface2: Color, val line: Color, val text: Color, val sub: Color,
          val accent: Color, val out: Color, val ok: Color, val bad: Color)

val DarkPal = Pal(Color(0xFF0A0E1A), Color(0xFF121829), Color(0xFF1A2238), Color(0xFF252E48), Color(0xFFEAEEF8), Color(0xFF8D98B4),
    Color(0xFF2F80FF), Color(0xFF1D4FB8), Color(0xFF3DDC84), Color(0xFFFF6B6B))
val LightPal = Pal(Color(0xFFF3F5FB), Color(0xFFFFFFFF), Color(0xFFE9EDF7), Color(0xFFD5DBEA), Color(0xFF0E1424), Color(0xFF5F6B88),
    Color(0xFF1F6BF0), Color(0xFFCFE0FF), Color(0xFF1E9E5A), Color(0xFFD64545))

val LocalPal = staticCompositionLocalOf { DarkPal }

@Composable fun NocTheme(content: @Composable () -> Unit) {
    val pal = if (isSystemInDarkTheme()) DarkPal else LightPal
    val scheme = (if (isSystemInDarkTheme()) darkColorScheme() else lightColorScheme()).copy(
        primary = pal.accent, background = pal.bg, surface = pal.surface, onBackground = pal.text, onSurface = pal.text,
        surfaceVariant = pal.surface2, onSurfaceVariant = pal.sub, error = pal.bad, outline = pal.line)
    CompositionLocalProvider(LocalPal provides pal) {
        MaterialTheme(colorScheme = scheme) { Surface(Modifier.fillMaxSize(), color = pal.bg) { content() } }
    }
}

// ---------------------------------------------------------------- icons (Material path data, drawn locally to avoid the heavy icon library)
private fun icon(name: String, d: String): ImageVector = ImageVector.Builder(name, 24.dp, 24.dp, 24f, 24f).addPath(
    pathData = PathParser().parsePathString(d).toNodes(), fill = SolidColor(Color.Black)).build()

object Ic {
    val Shield = icon("shield", "M12,1L3,5v6c0,5.55 3.84,10.74 9,12 5.16,-1.26 9,-6.45 9,-12V5l-9,-4z")
    val Chat = icon("chat", "M20,2H4c-1.1,0 -2,0.9 -2,2v18l4,-4h14c1.1,0 2,-0.9 2,-2V4c0,-1.1 -0.9,-2 -2,-2z")
    val Person = icon("person", "M12,12c2.21,0 4,-1.79 4,-4s-1.79,-4 -4,-4 -4,1.79 -4,4 1.79,4 4,4zM12,14c-2.67,0 -8,1.34 -8,4v2h16v-2c0,-2.66 -5.33,-4 -8,-4z")
    val Gear = icon("gear", "M19.14,12.94c0.04,-0.3 0.06,-0.61 0.06,-0.94c0,-0.32 -0.02,-0.64 -0.07,-0.94l2.03,-1.58c0.18,-0.14 0.23,-0.41 0.12,-0.61l-1.92,-3.32c-0.12,-0.22 -0.37,-0.29 -0.59,-0.22l-2.39,0.96c-0.5,-0.38 -1.03,-0.7 -1.62,-0.94L14.4,2.81c-0.04,-0.24 -0.24,-0.41 -0.48,-0.41h-3.84c-0.24,0 -0.43,0.17 -0.47,0.41L9.25,5.35C8.66,5.59 8.12,5.92 7.63,6.29L5.24,5.33c-0.22,-0.08 -0.47,0 -0.59,0.22L2.74,8.87C2.62,9.08 2.66,9.34 2.86,9.48l2.03,1.58C4.84,11.36 4.8,11.69 4.8,12s0.02,0.64 0.07,0.94l-2.03,1.58c-0.18,0.14 -0.23,0.41 -0.12,0.61l1.92,3.32c0.12,0.22 0.37,0.29 0.59,0.22l2.39,-0.96c0.5,0.38 1.03,0.7 1.62,0.94l0.36,2.54c0.05,0.24 0.24,0.41 0.48,0.41h3.84c0.24,0 0.44,-0.17 0.47,-0.41l0.36,-2.54c0.59,-0.24 1.13,-0.56 1.62,-0.94l2.39,0.96c0.22,0.08 0.47,0 0.59,-0.22l1.92,-3.32c0.12,-0.22 0.07,-0.47 -0.12,-0.61L19.14,12.94zM12,15.6c-1.98,0 -3.6,-1.62 -3.6,-3.6s1.62,-3.6 3.6,-3.6s3.6,1.62 3.6,3.6S13.98,15.6 12,15.6z")
    val Mic = icon("mic", "M12,14c1.66,0 2.99,-1.34 2.99,-3L15,5c0,-1.66 -1.34,-3 -3,-3S9,3.34 9,5v6c0,1.66 1.34,3 3,3zM17.3,11c0,3 -2.54,5.1 -5.3,5.1S6.7,14 6.7,11L5,11c0,3.41 2.72,6.23 6,6.72L11,21h2v-3.28c3.28,-0.48 6,-3.3 6,-6.72h-1.7z")
    val Send = icon("send", "M2.01,21L23,12 2.01,3 2,10l15,2 -15,2z")
    val Clip = icon("clip", "M16.5,6v11.5c0,2.21 -1.79,4 -4,4s-4,-1.79 -4,-4V5c0,-1.38 1.12,-2.5 2.5,-2.5s2.5,1.12 2.5,2.5v10.5c0,0.55 -0.45,1 -1,1s-1,-0.45 -1,-1V6H10v9.5c0,1.38 1.12,2.5 2.5,2.5s2.5,-1.12 2.5,-2.5V5c0,-2.21 -1.79,-4 -4,-4S7,2.79 7,5v12.5c0,3.04 2.46,5.5 5.5,5.5s5.5,-2.46 5.5,-5.5V6h-1.5z")
    val Play = icon("play", "M8,5v14l11,-7z")
    val Stop = icon("stop", "M6,6h12v12H6z")
    val Clock = icon("clock", "M11.99,2C6.47,2 2,6.48 2,12s4.47,10 9.99,10C17.52,22 22,17.52 22,12S17.52,2 11.99,2zM12,20c-4.42,0 -8,-3.58 -8,-8s3.58,-8 8,-8 8,3.58 8,8 -3.58,8 -8,8zM12.5,7H11v6l5.25,3.15 0.75,-1.23 -4.5,-2.67z")
    val Lock = icon("lock", "M18,8h-1V6c0,-2.76 -2.24,-5 -5,-5S7,3.24 7,6v2H6c-1.1,0 -2,0.9 -2,2v10c0,1.1 0.9,2 2,2h12c1.1,0 2,-0.9 2,-2V10c0,-1.1 -0.9,-2 -2,-2zM12,17c-1.1,0 -2,-0.9 -2,-2s0.9,-2 2,-2 2,0.9 2,2 -0.9,2 -2,2zM15.1,8H8.9V6c0,-1.71 1.39,-3.1 3.1,-3.1 1.71,0 3.1,1.39 3.1,3.1v2z")
    val Check = icon("check", "M9,16.17L4.83,12l-1.42,1.41L9,19 21,7l-1.41,-1.41z")
    val Search = icon("search", "M15.5,14h-0.79l-0.28,-0.27C15.41,12.59 16,11.11 16,9.5 16,5.91 13.09,3 9.5,3S3,5.91 3,9.5 5.91,16 9.5,16c1.61,0 3.09,-0.59 4.23,-1.57l0.27,0.28v0.79l5,4.99L20.49,19l-4.99,-5zM9.5,14C7.01,14 5,11.99 5,9.5S7.01,5 9.5,5 14,7.01 14,9.5 11.99,14 9.5,14z")
    val Back = icon("back", "M20,11H7.83l5.59,-5.59L12,4l-8,8 8,8 1.41,-1.41L7.83,13H20v-2z")
    val Add = icon("add", "M19,13h-6v6h-2v-6H5v-2h6V5h2v6h6v2z")
    val Chevron = icon("chev", "M10,6L8.59,7.41 13.17,12l-4.58,4.59L10,18l6,-6z")
}

@Composable fun Ico(v: ImageVector, tint: Color, size: Int = 24, modifier: Modifier = Modifier) =
    Image(v, null, modifier.size(size.dp), colorFilter = androidx.compose.ui.graphics.ColorFilter.tint(tint))

// ---------------------------------------------------------------- building blocks
@Composable fun Avatar(name: String, size: Int = 48) {
    val pal = LocalPal.current
    val hue = (name.hashCode() and 0x7fffffff) % 360
    val c = Color.hsv(hue.toFloat(), 0.45f, 0.75f)
    Box(Modifier.size(size.dp).clip(CircleShape).background(Brush.linearGradient(listOf(c, pal.accent))), contentAlignment = Alignment.Center) {
        Text(name.trim().take(1).uppercase().ifEmpty { "?" }, color = Color.White, fontSize = (size * 0.42f).sp, fontWeight = FontWeight.SemiBold)
    }
}

@Composable fun Card(modifier: Modifier = Modifier, content: @Composable ColumnScope.() -> Unit) {
    val pal = LocalPal.current
    Column(modifier.fillMaxWidth().clip(RoundedCornerShape(18.dp)).background(pal.surface).padding(16.dp), content = content)
}

@Composable fun Logo(size: Int = 72) {
    Box(Modifier.size(size.dp).clip(RoundedCornerShape((size * 0.22f).dp)).background(Color(0xFF05070D)), contentAlignment = Alignment.Center) {
        Image(androidx.compose.ui.res.painterResource(noc.app.R.drawable.ic_logo), null, Modifier.size((size * 1.1f).dp))
    }
}

@Composable fun PrimaryButton(text: String, onClick: () -> Unit, modifier: Modifier = Modifier) {
    val pal = LocalPal.current
    Button(onClick, modifier.fillMaxWidth().height(50.dp), shape = RoundedCornerShape(14.dp), colors = ButtonDefaults.buttonColors(containerColor = pal.accent, contentColor = Color.White)) { Text(text) }
}

@Composable fun SecondaryButton(text: String, onClick: () -> Unit, modifier: Modifier = Modifier) {
    val pal = LocalPal.current
    Button(onClick, modifier.fillMaxWidth().height(50.dp), shape = RoundedCornerShape(14.dp), colors = ButtonDefaults.buttonColors(containerColor = pal.surface2, contentColor = pal.text)) { Text(text) }
}

@Composable fun Pill(text: String, selected: Boolean, onClick: () -> Unit) {
    val pal = LocalPal.current
    Box(Modifier.clip(RoundedCornerShape(50)).background(if (selected) pal.accent else pal.surface).clickableNoRipple(onClick).padding(horizontal = 18.dp, vertical = 9.dp)) {
        Text(text, color = if (selected) Color.White else pal.sub, fontSize = 14.sp, maxLines = 1)
    }
}

fun Modifier.clickableNoRipple(onClick: () -> Unit): Modifier = clickable(onClick = onClick)

@Composable fun Page(title: String, onBack: (() -> Unit)? = null, actions: @Composable RowScope.() -> Unit = {}, body: @Composable ColumnScope.() -> Unit) {
    val pal = LocalPal.current
    Column(Modifier.fillMaxSize().systemBarsPadding().padding(horizontal = 16.dp)) {
        Row(Modifier.fillMaxWidth().height(56.dp), verticalAlignment = Alignment.CenterVertically) {
            if (onBack != null) Box(Modifier.clickableNoRipple(onBack).padding(end = 12.dp, top = 8.dp, bottom = 8.dp)) { Ico(Ic.Back, pal.text) }
            Text(title, color = pal.text, fontSize = 22.sp, fontWeight = FontWeight.SemiBold, modifier = Modifier.weight(1f))
            actions()
        }
        body()
    }
}

@Composable fun Scrolling(modifier: Modifier = Modifier, body: @Composable ColumnScope.() -> Unit) =
    Column(modifier.fillMaxWidth().verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(12.dp), content = body)

@Composable fun BottomBar(current: Screen, go: (Screen) -> Unit) {
    val pal = LocalPal.current
    data class Tab(val s: Screen, val icon: ImageVector, val label: Int)
    val tabs = listOf(Tab(Screen.Chats, Ic.Chat, noc.app.R.string.nav_chats), Tab(Screen.Contacts, Ic.Person, noc.app.R.string.nav_contacts),
        Tab(Screen.Protect, Ic.Shield, noc.app.R.string.nav_protect), Tab(Screen.Settings, Ic.Gear, noc.app.R.string.nav_settings))
    Row(Modifier.fillMaxWidth().background(pal.surface).navigationBarsPadding().padding(vertical = 8.dp), horizontalArrangement = Arrangement.SpaceAround) {
        tabs.forEach { t ->
            val sel = t.s::class == current::class
            Column(Modifier.clickableNoRipple { go(t.s) }.padding(horizontal = 12.dp, vertical = 4.dp), horizontalAlignment = Alignment.CenterHorizontally) {
                Ico(t.icon, if (sel) pal.accent else pal.sub, 24)
                Text(androidx.compose.ui.res.stringResource(t.label), color = if (sel) pal.accent else pal.sub, fontSize = 11.sp)
            }
        }
    }
}

/** Page with the bottom navigation, used by the four main tabs. */
@Composable fun Tabbed(current: Screen, go: (Screen) -> Unit, content: @Composable ColumnScope.() -> Unit) {
    Column(Modifier.fillMaxSize()) {
        Column(Modifier.weight(1f).fillMaxWidth(), content = content)
        BottomBar(current, go)
    }
}

fun qrBitmap(text: String, size: Int = 640): Bitmap {
    val m = QRCodeWriter().encode(text, BarcodeFormat.QR_CODE, size, size)
    val px = IntArray(size * size) { if (m.get(it % size, it / size)) AColor.BLACK else AColor.WHITE }
    return Bitmap.createBitmap(px, size, size, Bitmap.Config.ARGB_8888)
}

@Composable fun QrImage(text: String) {
    val bmp = remember(text) { qrBitmap(text) }
    Box(Modifier.fillMaxWidth().clip(RoundedCornerShape(16.dp)).background(Color.White).padding(12.dp)) {
        Image(bmp.asImageBitmap(), null, Modifier.fillMaxWidth().aspectRatio(1f))
    }
}

/** Static bars that look like a voice waveform; seeded by message id so it stays stable. */
@Composable fun Waveform(seed: Long, color: Color, modifier: Modifier = Modifier) {
    Canvas(modifier.height(28.dp).width(120.dp)) {
        val n = 28; val step = size.width / n
        val rnd = java.util.Random(seed)
        for (i in 0 until n) {
            val h = size.height * (0.25f + 0.75f * rnd.nextFloat())
            drawLine(color, androidx.compose.ui.geometry.Offset(i * step + step / 2, (size.height - h) / 2),
                androidx.compose.ui.geometry.Offset(i * step + step / 2, (size.height + h) / 2), strokeWidth = step * 0.5f)
        }
    }
}
