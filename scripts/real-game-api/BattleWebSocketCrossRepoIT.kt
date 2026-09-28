package opensamguk.battlewebsockettest

import java.io.File
import java.net.Socket
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import opensamguk.common.world.WorldId
import opensamguk.gameapi.battle.realtime.BattleJoinTicketService
import opensamguk.gameapi.battle.realtime.BattleWebSocketConfiguration
import opensamguk.gameapi.config.GameApiProcessWorld
import opensamguk.gameapi.owner.GeneralResolver
import opensamguk.infra.battle.realtime.BattleSessionHead
import opensamguk.infra.battle.realtime.BattleSessionPhase
import opensamguk.infra.battle.realtime.BattleSessionStore
import opensamguk.infra.battle.realtime.FrozenBattleParticipant
import opensamguk.infra.battle.realtime.FrozenBattleTicket
import org.mockito.Mockito.mock
import org.mockito.Mockito.`when`
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.SpringBootConfiguration
import org.springframework.boot.autoconfigure.EnableAutoConfiguration
import org.springframework.boot.autoconfigure.data.redis.RedisAutoConfiguration
import org.springframework.boot.autoconfigure.data.redis.RedisRepositoriesAutoConfiguration
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration
import org.springframework.boot.autoconfigure.orm.jpa.HibernateJpaAutoConfiguration
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration
import org.springframework.boot.autoconfigure.security.servlet.UserDetailsServiceAutoConfiguration
import org.springframework.boot.actuate.autoconfigure.security.servlet.ManagementWebSecurityAutoConfiguration
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Import

/** CI-only wiring of the product PR's production admission and signer; no database or live key. */
@SpringBootConfiguration
@EnableAutoConfiguration(exclude = [DataSourceAutoConfiguration::class,
    HibernateJpaAutoConfiguration::class, RedisAutoConfiguration::class,
    RedisRepositoriesAutoConfiguration::class, SecurityAutoConfiguration::class,
    UserDetailsServiceAutoConfiguration::class, ManagementWebSecurityAutoConfiguration::class])
@Import(BattleWebSocketConfiguration::class)
private class BattleWebSocketCrossRepoTestApplication {
    @Bean fun store(): BattleSessionStore = mock(BattleSessionStore::class.java)
    @Bean fun tickets(store: BattleSessionStore): BattleJoinTicketService =
        BattleJoinTicketService(store, ByteArray(32) { 7 },
            Clock.fixed(Instant.parse("2026-09-29T00:00:00Z"), ZoneOffset.UTC), "pep")
    @Bean fun generals(): GeneralResolver = mock(GeneralResolver::class.java)
    @Bean fun processWorld() = GameApiProcessWorld(1)
}

@SpringBootTest(classes = [BattleWebSocketCrossRepoTestApplication::class],
    webEnvironment = SpringBootTest.WebEnvironment.DEFINED_PORT,
    properties = ["server.port=8081", "server.address=0.0.0.0",
        "battle.join-ticket.enabled=true", "battle.websocket.allowed-origins=http://localhost"])
class BattleWebSocketCrossRepoIT @Autowired constructor(
    private val tickets: BattleJoinTicketService,
    private val generals: GeneralResolver,
    private val store: BattleSessionStore,
) {
    private val world = WorldId(1)
    private val now = Instant.parse("2026-09-29T00:00:00Z")
    private val participant = FrozenBattleParticipant(1, 42, 7, "ATTACKER", 3)
    private val ticket = FrozenBattleTicket(world, "battle-1", "{}", "a".repeat(64),
        "a".repeat(64), "a".repeat(64), "a".repeat(64), 17, 4, 2,
        now.minusSeconds(60), now.plusSeconds(300), listOf(participant))

    private fun handshake(path: String, token: String, origin: String = "http://localhost",
                          extra: String = ""): String = Socket("127.0.0.1", 18080).use { socket ->
        socket.soTimeout = 5000
        socket.getOutputStream().write(("GET $path HTTP/1.1\r\n" +
            "Host: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
            "Sec-WebSocket-Version: 13\r\n" +
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
            "Sec-WebSocket-Protocol: battle.v1, $token\r\n" +
            "Origin: $origin\r\n$extra\r\n").toByteArray(Charsets.US_ASCII))
        val reader = socket.getInputStream().bufferedReader(Charsets.US_ASCII)
        val lines = mutableListOf<String>()
        while (true) {
            val line = reader.readLine() ?: break
            if (line.isEmpty()) break
            lines += line
        }
        lines.joinToString("\n")
    }

    @Test
    fun `real signer admission through nginx and registry revocation`() {
        `when`(store.ticket(world, "battle-1")).thenReturn(ticket)
        `when`(store.head(world, "battle-1")).thenReturn(BattleSessionHead(world, "battle-1",
            BattleSessionPhase.RUNNING, 1, 0, 0, 0, "actor", now.plusSeconds(30),
            ticket.joinDeadlineAt, ticket.deadlineAt))
        `when`(generals.resolveGeneralId(42L)).thenReturn(7)
        val token = tickets.issue(world, "battle-1", 42, 7)
        val path = "/api/battle-ws/pep/1/battle-1"
        val accepted = handshake(path, token,
            extra = "Authorization: Bearer long\r\nCookie: sam_access=long\r\nProxy-Authorization: Basic long\r\n")
        assertContains(accepted, "101", "nginx -> game-api signed handshake")
        assertContains(accepted.lowercase(), "sec-websocket-protocol: battle.v1")
        assertFalse(accepted.contains(token))

        val badSignature = token.dropLast(1) + if (token.last() == 'A') 'B' else 'A'
        assertContains(handshake(path, badSignature), "403", "game-api signature boundary")
        assertContains(handshake(path, token, origin = "http://foreign.example"), "403",
            "game-api Origin boundary")
        assertContains(handshake("/api/battle-ws/other/1/battle-1", token), "403",
            "game-api server binding through an allowlisted nginx target")

        File(System.getenv("BATTLE_WS_MAP_FILE")).writeText("")
        val container = System.getenv("BATTLE_WS_NGINX_CONTAINER")
        val reload = ProcessBuilder("docker", "exec", container, "nginx", "-s", "reload")
            .redirectErrorStream(true).start()
        val reloadOutput = reload.inputStream.bufferedReader().readText()
        assertTrue(reload.waitFor() == 0, "nginx reload failed: $reloadOutput")
        val deadline = System.nanoTime() + 5_000_000_000L
        while (true) {
            val response = handshake(path, token)
            if (response.contains("404")) break
            assertContains(response, "101", "old nginx worker during reload")
            assertTrue(System.nanoTime() < deadline, "nginx deletion did not revoke within 5s")
            Thread.sleep(100)
        }
    }
}
