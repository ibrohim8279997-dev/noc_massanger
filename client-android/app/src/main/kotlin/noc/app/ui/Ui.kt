package noc.app.ui

import android.graphics.Bitmap
import android.graphics.Color as AColor
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.unit.dp
import com.google.zxing.BarcodeFormat
import com.google.zxing.qrcode.QRCodeWriter

sealed class Screen {
    object Lock : Screen(); class Problem(val key: String) : Screen(); object Setup : Screen(); object Chats : Screen()
    class Chat(val id: Long) : Screen(); object Settings : Screen(); object Meet : Screen(); object Admin : Screen(); class Safety(val id: Long) : Screen()
}

class UiState {
    var screen by mutableStateOf<Screen>(Screen.Lock)
    var tick by mutableIntStateOf(0)
    var error by mutableStateOf<String?>(null)
}

fun qrBitmap(text: String, size: Int = 640): Bitmap {
    val m = QRCodeWriter().encode(text, BarcodeFormat.QR_CODE, size, size)
    val px = IntArray(size * size) { if (m.get(it % size, it / size)) AColor.BLACK else AColor.WHITE }
    return Bitmap.createBitmap(px, size, size, Bitmap.Config.ARGB_8888)
}

@Composable fun QrImage(text: String) {
    val bmp = remember(text) { qrBitmap(text) }
    Image(bmp.asImageBitmap(), null, Modifier.fillMaxWidth().aspectRatio(1f))
}

@Composable fun NocTheme(content: @Composable () -> Unit) {
    MaterialTheme(colorScheme = if (androidx.compose.foundation.isSystemInDarkTheme()) darkColorScheme() else lightColorScheme()) {
        Surface(Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) { content() }
    }
}

@Composable fun Page(title: String, onBack: (() -> Unit)? = null, actions: @Composable RowScope.() -> Unit = {}, body: @Composable ColumnScope.() -> Unit) {
    Column(Modifier.fillMaxSize().systemBarsPadding().padding(16.dp)) {
        Row(verticalAlignment = androidx.compose.ui.Alignment.CenterVertically) {
            if (onBack != null) TextButton(onClick = onBack) { Text("←") }
            Text(title, style = MaterialTheme.typography.titleLarge, modifier = Modifier.weight(1f))
            actions()
        }
        Spacer(Modifier.height(12.dp))
        body()
    }
}

@Composable fun Scrolling(body: @Composable ColumnScope.() -> Unit) =
    Column(Modifier.fillMaxWidth().verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(12.dp), content = body)
