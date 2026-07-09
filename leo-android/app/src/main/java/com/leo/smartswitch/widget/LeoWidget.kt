package com.leo.smartswitch.widget

import android.content.Context
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.glance.GlanceId
import androidx.glance.GlanceModifier
import androidx.glance.Image
import androidx.glance.ImageProvider
import androidx.glance.action.ActionParameters
import androidx.glance.action.actionParametersOf
import androidx.glance.action.clickable
import androidx.glance.appwidget.GlanceAppWidget
import androidx.glance.appwidget.GlanceAppWidgetReceiver
import androidx.glance.appwidget.action.ActionCallback
import androidx.glance.appwidget.action.actionRunCallback
import androidx.glance.appwidget.cornerRadius
import androidx.glance.appwidget.provideContent
import androidx.glance.background
import androidx.glance.layout.Alignment
import androidx.glance.layout.Box
import androidx.glance.layout.Column
import androidx.glance.layout.Row
import androidx.glance.layout.Spacer
import androidx.glance.layout.fillMaxSize
import androidx.glance.layout.fillMaxWidth
import androidx.glance.layout.height
import androidx.glance.layout.padding
import androidx.glance.layout.width
import androidx.glance.text.FontWeight
import androidx.glance.text.Text
import androidx.glance.text.TextStyle
import androidx.glance.unit.ColorProvider
import com.leo.smartswitch.DeviceApi
import com.leo.smartswitch.DeviceStore
import com.leo.smartswitch.R
import com.leo.smartswitch.SavedDevice
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch

private val BG = Color(0xFF0A0D10)
private val SURFACE = Color(0xFF161B22)
private val ACCENT = Color(0xFF00F2FF)
private val ON_ACCENT = Color(0xFF003135)
private val OFF = Color(0xFF21262D)
private val TXT = Color(0xFFF0F4F8)
private val MUT = Color(0xFF7E8C9A)

val KEY_ID = ActionParameters.Key<String>("id")
val KEY_IDX = ActionParameters.Key<Int>("idx")
val KEY_ON = ActionParameters.Key<Boolean>("on")
val KEY_MASTER_ON = ActionParameters.Key<Boolean>("master_on")

class LeoWidget : GlanceAppWidget() {
    override suspend fun provideGlance(context: Context, id: GlanceId) {
        val store = DeviceStore(context)
        val devices = store.getDevices().take(2)
        
        val states = coroutineScope {
            devices.map { d ->
                async { d to DeviceApi.state(d.baseUrl(), d.token) }
            }.awaitAll()
        }

        provideContent { Content(states) }
    }

    @Composable
    private fun Content(states: List<Pair<SavedDevice, com.leo.smartswitch.DeviceState?>>) {
        Box(GlanceModifier.fillMaxSize().background(BG).padding(12.dp)) {
            Column(GlanceModifier.fillMaxSize()) {
                // Header with Master Controls
                Row(GlanceModifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        "LEO",
                        style = TextStyle(color = ColorProvider(ACCENT), fontSize = 14.sp, fontWeight = FontWeight.Bold),
                        modifier = GlanceModifier.defaultWeight()
                    )
                    
                    MasterPill("ON", ACCENT, actionRunCallback<MasterAllAction>(actionParametersOf(KEY_MASTER_ON to true)))
                    Spacer(GlanceModifier.width(6.dp))
                    MasterPill("OFF", OFF, actionRunCallback<MasterAllAction>(actionParametersOf(KEY_MASTER_ON to false)))
                    
                    Spacer(GlanceModifier.width(10.dp))
                    Image(
                        provider = ImageProvider(R.drawable.ic_refresh),
                        contentDescription = "Refresh",
                        modifier = GlanceModifier.width(20.dp).height(20.dp)
                            .clickable(actionRunCallback<RefreshAction>())
                    )
                }
                
                Spacer(GlanceModifier.height(12.dp))

                if (states.isEmpty()) {
                    Box(GlanceModifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                        Text("No devices saved", style = TextStyle(color = ColorProvider(MUT), fontSize = 12.sp))
                    }
                    return@Column
                }

                states.forEachIndexed { idx, (device, state) ->
                    DeviceRow(device, state)
                    if (idx < states.size - 1) Spacer(GlanceModifier.height(12.dp))
                }
            }
        }
    }

    @Composable
    private fun MasterPill(label: String, color: Color, onClick: androidx.glance.action.Action) {
        Box(
            modifier = GlanceModifier.width(48.dp).height(24.dp).cornerRadius(12.dp).background(color).clickable(onClick),
            contentAlignment = Alignment.Center
        ) {
            Text(
                label,
                style = TextStyle(
                    color = ColorProvider(if (color == ACCENT) ON_ACCENT else TXT),
                    fontSize = 9.sp, fontWeight = FontWeight.Bold
                )
            )
        }
    }

    @Composable
    private fun DeviceRow(device: SavedDevice, state: com.leo.smartswitch.DeviceState?) {
        Column(GlanceModifier.fillMaxWidth().background(SURFACE).cornerRadius(16.dp).padding(10.dp)) {
            Row(GlanceModifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                Text(
                    device.name,
                    style = TextStyle(color = ColorProvider(TXT), fontSize = 13.sp, fontWeight = FontWeight.Bold),
                    modifier = GlanceModifier.defaultWeight()
                )
                if (state != null) {
                    Text(
                        java.util.Locale.US.let { String.format(it, "%.1fW", state.totalWatts) },
                        style = TextStyle(color = ColorProvider(ACCENT), fontSize = 10.sp)
                    )
                    Spacer(GlanceModifier.width(6.dp))
                }
                Box(
                    GlanceModifier.width(8.dp).height(8.dp).cornerRadius(4.dp)
                        .background(if (state != null) ACCENT else Color.Red)
                ) {}
            }
            
            Spacer(GlanceModifier.height(8.dp))
            
            if (state != null) {
                Row(GlanceModifier.fillMaxWidth()) {
                    state.relays.take(4).forEachIndexed { i, r ->
                        RelayButton(
                            label = r.name.take(1).uppercase() + (i + 1),
                            isOn = r.on,
                            modifier = GlanceModifier.defaultWeight(),
                            onClick = actionRunCallback<ToggleAction>(actionParametersOf(
                                KEY_ID to device.id,
                                KEY_IDX to i, 
                                KEY_ON to !r.on
                            ))
                        )
                        if (i < 3) Spacer(GlanceModifier.width(6.dp))
                    }
                }
            } else {
                Text("Unreachable", style = TextStyle(color = ColorProvider(MUT), fontSize = 11.sp), modifier = GlanceModifier.fillMaxWidth())
            }
        }
    }

    @Composable
    private fun RelayButton(label: String, isOn: Boolean, modifier: GlanceModifier, onClick: androidx.glance.action.Action) {
        Box(
            modifier = modifier.height(34.dp).cornerRadius(10.dp)
                .background(if (isOn) ACCENT else OFF)
                .clickable(onClick),
            contentAlignment = Alignment.Center
        ) {
            Text(label, style = TextStyle(color = ColorProvider(if (isOn) ON_ACCENT else TXT), fontSize = 10.sp, fontWeight = FontWeight.Bold))
        }
    }
}

class LeoWidgetReceiver : GlanceAppWidgetReceiver() {
    override val glanceAppWidget: GlanceAppWidget = LeoWidget()
}

class ToggleAction : ActionCallback {
    override suspend fun onAction(context: Context, glanceId: GlanceId, parameters: ActionParameters) {
        val store = DeviceStore(context)
        val id = parameters[KEY_ID] ?: return
        val idx = parameters[KEY_IDX] ?: return
        val on = parameters[KEY_ON] ?: return
        val device = store.getDevices().find { it.id == id } ?: return
        DeviceApi.setRelay(device.baseUrl(), device.token, idx, on)
        LeoWidget().update(context, glanceId)
    }
}

class MasterAllAction : ActionCallback {
    override suspend fun onAction(context: Context, glanceId: GlanceId, parameters: ActionParameters) {
        val store = DeviceStore(context)
        val on = parameters[KEY_MASTER_ON] ?: return
        val devices = store.getDevices()
        coroutineScope {
            devices.forEach { device ->
                launch { DeviceApi.setAll(device.baseUrl(), device.token, on) }
            }
        }
        LeoWidget().update(context, glanceId)
    }
}

class RefreshAction : ActionCallback {
    override suspend fun onAction(context: Context, glanceId: GlanceId, parameters: ActionParameters) {
        LeoWidget().update(context, glanceId)
    }
}
