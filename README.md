# M295-HTTP-Authentication-Methods

- [M295-HTTP-Authentication-Methods](#m295-http-authentication-methods)
  - [1. Authentifizierung vs Autorisierung](#1-authentifizierung-vs-autorisierung)
    - [1.1 Authentifizierung bedeutung:](#11-authentifizierung-bedeutung)
    - [1.2 Beispiel für Authentifizierung:](#12-beispiel-für-authentifizierung)
    - [1.3 Authentifizierungsmethoden:](#13-authentifizierungsmethoden)
    - [1.4 Autorisierung bedeutung:](#14-autorisierung-bedeutung)
    - [1.5 Beispiel für Autorisierung:](#15-beispiel-für-autorisierung)
    - [1.6 Autorisierungsmethoden:](#16-autorisierungsmethoden)
  - [2. Wie funktioniert Basic Authentication?](#2-wie-funktioniert-basic-authentication)
  - [3. API-Key](#3-api-key)
    - [3.1 Was ist ein API-Key?](#31-was-ist-ein-api-key)
    - [3.2 Verwendung von API-Keys](#32-verwendung-von-api-keys)
      - [Beispiel:](#beispiel)
    - [3.3 Implementierung von API-Keys](#33-implementierung-von-api-keys)
      - [Beispiel für Custom Middleware:](#beispiel-für-custom-middleware)
    - [3.4 Sicherheit von API-Keys](#34-sicherheit-von-api-keys)
      - [Beispiel für Hashing:](#beispiel-für-hashing)
    - [3.5 Zusammenfassung](#35-zusammenfassung)
  - [4. JWT (JSON Web Tokens)](#4-jwt-json-web-tokens)
    - [4.1 Aufbau / Struktur](#41-aufbau--struktur)
    - [4.2 Wie funktioniert die JWT-Authentifizierung](#42-wie-funktioniert-die-jwt-authentifizierung)
    - [4.3 Vorteile](#43-vorteile)
    - [4.4 Nachteile](#44-nachteile)
  - [5. ASP.NET: Die Bedeutung der Attribute \[Authorize\] und \[AllowAnonymous\]](#5-aspnet-die-bedeutung-der-attribute-authorize-und-allowanonymous)
    - [5.1 Einleitung](#51-einleitung)
    - [5.2 \[Authorize\]](#52-authorize)
    - [5.3 \[AllowAnonymous\]](#53-allowanonymous)
    - [5.4 Beispiel:](#54-beispiel)
  - [6. Übersicht und Erläuterung zu den HTTP-Statuscodes](#6-übersicht-und-erläuterung-zu-den-http-statuscodes)
    - [6.1 Unerlaubter Zugriff (4xx Statuscodes)](#61-unerlaubter-zugriff-4xx-statuscodes)
      - [Beispiele aus dem Backend-Projekt](#beispiele-aus-dem-backend-projekt)
  - [7. Zusammenfassung und Ausblick (Fazit)](#7-zusammenfassung-und-ausblick-fazit)
    - [7.1 Wichtige Erkenntnisse und Best Practices](#71-wichtige-erkenntnisse-und-best-practices)
    - [7.2 Zukünftige Trends in der Authentifizierung](#72-zukünftige-trends-in-der-authentifizierung)
    - [7.3 Abschlussbemerkung](#73-abschlussbemerkung)


## 1. Authentifizierung vs Autorisierung

![bild](https://assets.f-secure.com/i/illustrations/what-is-two-factor-authentication.png)
### 1.1 Authentifizierung bedeutung: 

Authentifizierung ist der Prozess der Überprüfung der Identität einer Person oder eines Geräts.

### 1.2 Beispiel für Authentifizierung:

Ein Benutzer möchte sich an einem öffentlichen WLAN-Netzwerk anmelden. Er wird aufgefordert,
seine Anmeldeinformationen einzugeben, um zu bestätigen, dass er ein berechtigter Benutzer ist.

### 1.3 Authentifizierungsmethoden:

Passwort: Der Benutzer gibt ein Passwort ein, das mit einem in einer Datenbank gespeicherten Passwort
verglichen wird.

Zertifikat: Der Benutzer präsentiert ein Zertifikat, das seine Identität bestätigt.

Biometrie: Der Benutzer verwendet seine biometrischen Daten, z. B. seinen Fingerabdruck oder
sein Gesicht, um sich zu authentifizieren.

---

![bild](https://supertokens.com/covers/user_roles_cover.png)

### 1.4 Autorisierung bedeutung:

Autorisierung ist der Prozess der Überprüfung, ob eine Person oder ein Gerät autorisiert ist, auf
eine Ressource zuzugreifen oder eine Aktion auszuführen.

### 1.5 Beispiel für Autorisierung:

Ein Mitarbeiter möchte sich in sein Bürogebäude begeben. Er wird von einem Sicherheitsbeamten 
aufgefordert, seinen Ausweis vorzuweisen, um zu bestätigen, dass er ein Mitarbeiter des Unternehmens ist.

### 1.6 Autorisierungsmethoden: 

Rollenbasierte Autorisierung: Der Benutzer wird einer Rolle zugeordnet, die bestimmte Berechtigungen 
enthält.

Ressourcenbasierte Autorisierung: Der Benutzer wird autorisiert, auf bestimmte Ressourcen zuzugreifen.

Berechtigungsbasierte Autorisierung: Der Benutzer wird autorisiert, bestimmte Aktionen auszuführen.


 ## 2. Wie funktioniert Basic Authentication?

Basic Authentication ist eine einfache Authentifizierungsmethode, die auf dem Übertragen von Benutzername und Passwort in Base64-codierter Form basiert. Hier ist eine Schritt-für-Schritt-Anleitung, wie Basic Authentication funktioniert:

1.  Anfrage des Clients:

    -   Der Client sendet eine HTTP-Anfrage an den Server, die eine geschützte Ressource oder Aktion erfordert.

2.  Antwort des Servers:

    -   Der Server erkennt, dass die Anfrage eine geschützte Ressource betrifft und antwortet mit einem HTTP-Statuscode 401 Unauthorized.

3.  Aufforderung zur Authentifizierung:

    -   Die Antwort des Servers enthält auch einen Header namens "WWW-Authenticate", der den Client auffordert, sich zu authentifizieren. Hier wird die Basic Authentication verwendet.

4.  Client sendet Authentifizierungsinformationen:

    -   Der Client konstruiert einen "Authorization"-Header, der das Wort "Basic" gefolgt von einem Leerzeichen und dann dem Base64-codierten Benutzernamen und Passwort enthält.

        httpCopy code

        `Authorization: Basic <base64_encoded_username_and_password>`

5.  Server authentifiziert den Benutzer:

    -   Der Server entschlüsselt den Base64-codierten Header und extrahiert Benutzername und Passwort. Dann authentifiziert er den Benutzer anhand der bereitgestellten Informationen.


6.  Zugriff gewährt oder verweigert:

    -   Wenn die Authentifizierung erfolgreich ist, gewährt der Server Zugriff auf die angeforderte Ressource und sendet die entsprechende Antwort. Andernfalls bleibt der Zugriff verweigert, und der Server sendet erneut einen HTTP-Statuscode 401 Unauthorized.

Es ist wichtig zu beachten, dass Basic Authentication unsicher ist, wenn es nicht über eine sichere Verbindung (HTTPS) verwendet wird, da Benutzername und Passwort im Klartext übertragen werden. Aus diesem Grund wird heute oft empfohlen, sicherere Authentifizierungsmethoden wie OAuth 2.0 oder JWT zu verwenden, insbesondere in öffentlichen Netzwerken.

## 3. API-Key

### 3.1 Was ist ein API-Key?

Ein API-Key ist ein einzigartiger Identifikator, der oft zur Authentifizierung eines Clients bei der Nutzung einer API verwendet wird. Er dient als eine Art Passwort, um sicherzustellen, dass nur autorisierte Benutzer auf die API zugreifen können.

![bild](https://www.kai-waehner.de/wp-content/uploads/2020/05/Middleware-API-Management-1-2048x821.png)

### 3.2 Verwendung von API-Keys

API-Keys werden in den Header oder die URL einer HTTP-Anfrage eingefügt. Wenn eine Anfrage an den Server gesendet wird, überprüft dieser den API-Key, um sicherzustellen, dass er gültig ist und dass der Client die erforderlichen Berechtigungen hat.

#### Beispiel:

In unserem Projekt könnte ein API-Key wie folgt verwendet werden:

```
GET /api/serviceorders
Authorization: ApiKey 123456789abcdef
```

Hier wird der API-Key im `Authorization`-Header der Anfrage gesendet.

### 3.3 Implementierung von API-Keys

In unserer Anwendung könnten wir eine Custom Middleware verwenden, um API-Keys zu überprüfen. Diese Middleware würde jede Anfrage abfangen und den API-Key überprüfen. Bei einer gültigen Anfrage würde der Zugriff gewährt; bei einer ungültigen würde ein Fehler zurückgegeben.

#### Beispiel für Custom Middleware:

```csharp
public class ApiKeyMiddleware
{
    private readonly RequestDelegate _next;
    private const string ApiKeyHeaderName = "Authorization";

    public ApiKeyMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        if (!context.Request.Headers.TryGetValue(ApiKeyHeaderName, out var extractedApiKey))
        {
            context.Response.StatusCode = 401; // Unauthorized
            await context.Response.WriteAsync("API Key is missing");
            return;
        }

        if (!ApiKeyService.IsApiKeyValid(extractedApiKey))
        {
            context.Response.StatusCode = 403; // Forbidden
            await context.Response.WriteAsync("Invalid API Key");
            return;
        }

        await _next(context);
    }
}
```

In diesem Beispiel prüft die Middleware den API-Key in jedem Request. Wenn der API-Key fehlt oder ungültig ist, wird die Anfrage abgelehnt.

### 3.4 Sicherheit von API-Keys

API-Keys sollten sicher behandelt werden, da sie den Zugang zu wichtigen Ressourcen ermöglichen. Es ist empfehlenswert, sie mit Hashing-Funktionen zu speichern und zu überprüfen. Hashing stellt sicher, dass der tatsächliche Schlüssel nicht im Klartext gespeichert wird, was die Sicherheit erhöht.

#### Beispiel für Hashing:

```csharp
public static bool IsApiKeyValid(string apiKey)
{
    // Stellt eine Verbindung zur Datenbank her und prüft den gehashten API-Key
}
```

In diesem Fall wird der API-Key gehasht und mit einem in der Datenbank gespeicherten gehashten Wert verglichen.

### 3.5 Zusammenfassung

API-Keys sind ein wichtiger Bestandteil der Authentifizierung und Autorisierung in Web-APIs. Sie müssen sicher verwaltet und überprüft werden, um den Zugriff auf sensible Daten zu kontrollieren. In unserem Projekt nutzen wir Custom Middleware und Hashing-Techniken, um die Sicherheit und Integrität unserer API zu gewährleisten.

## 4. JWT (JSON Web Tokens)

JWTs sind eine kompakte und selbst-enthaltene Methode für die sichere Übertragung von Informationen zwischen Parteien als JSON-Objekt. Sie können zum Authentifizieren und Autorisieren von Benutzern in Web-Anwendungen verwendet werden.

### 4.1 Aufbau / Struktur

Ein JWT besteht aus drei Teilen: Header, Payload und Signature. Jeder Teil wird durch Punkte (`.`) getrennt.

- **Header**: Enthält Informationen über den Typ des Tokens (typischerweise JWT) und den verwendeten Algorithmus zur Verschlüsselung (z.B. HMAC SHA256 oder RSA).

- **Payload**: Enthält die eigentlichen Daten (Claims). Diese können Benutzerinformationen oder andere notwendige Daten enthalten. Es gibt drei Arten von Claims: Registered, Public und Private Claims.

- **Signature**: Wird verwendet, um zu überprüfen, ob der Absender des Tokens legitim ist und ob das Token während der Übertragung verändert wurde.

![bild](https://research.securitum.com/wp-content/uploads/sites/2/2019/10/jwt_ng1_en.png)

### 4.2 Wie funktioniert die JWT-Authentifizierung

1. Der Benutzer meldet sich mit seinen Anmeldedaten an.
2. Der Server überprüft die Anmeldedaten und erstellt ein JWT mit einem geheimen Schlüssel.
3. Das JWT wird an den Benutzer zurückgeschickt.
4. Bei nachfolgenden Anfragen sendet der Benutzer das JWT mit, typischerweise im `Authorization` Header.
5. Der Server überprüft das JWT anhand des geheimen Schlüssels und gewährt bei Gültigkeit Zugriff.

![bild](https://www.freecodecamp.org/news/content/images/2023/01/token-based-authentication.jpg)

### 4.3 Vorteile

- **Kompakt**: Kann leicht durch URL, POST-Parameter oder im HTTP-Header übertragen werden.
- **Selbst-enthaltend**: Die Payload enthält alle notwendigen Informationen über den Benutzer, wodurch die Notwendigkeit von weiteren Datenbankabfragen reduziert wird.
- **Skalierbarkeit**: Da keine Benutzersitzung auf dem Server gespeichert wird, eignen sich JWTs gut für verteilte Systeme.

### 4.4 Nachteile

- **Sicherheitsrisiken**: Wenn der geheime Schlüssel kompromittiert wird, können alle Tokens gefälscht werden.
- **Kein State**: JWTs sind stateless. Das bedeutet, dass einmal ausgestellte Tokens bis zum Ablauf gültig bleiben, selbst wenn das Benutzerkonto deaktiviert wird.
- **Speicherung**: Der Client muss das Token sicher speichern, um es vor XSS- und CSRF-Angriffen zu schützen.


## 5. ASP.NET: Die Bedeutung der Attribute [Authorize] und [AllowAnonymous]
 
### 5.1 Einleitung
ASP.NET ist ein beliebtes Framework für die Entwicklung von Webanwendungen. In ASP.NET gibt es verschiedene Attribute, die dazu dienen, den Zugriff auf bestimmte Teile der Anwendung zu steuern. Zwei wichtige Attribute in diesem Kontext sind `[Authorize]` und `[AllowAnonymous]`.
 
### 5.2 [Authorize]
Das `[Authorize]`-Attribut spielt eine zentrale Rolle in der Authentifizierung und Autorisierung von Benutzern. Es wird verwendet, um sicherzustellen, dass nur authentifizierte Benutzer auf eine bestimmte Ressource oder Aktion zugreifen können. Wenn ein Controller oder eine Aktion mit `[Authorize]` markiert ist, müssen Benutzer angemeldet sein, um darauf zuzugreifen.
 
### 5.3 [AllowAnonymous]
Im Gegensatz dazu steht das [AllowAnonymous]-Attribut. Dieses Attribut wird verwendet, um öffentlichen Zugriff auf eine Ressource oder Aktion zu ermöglichen, unabhängig davon, ob der Benutzer authentifiziert ist oder nicht.
 
### 5.4 Beispiel:
 
```csharp
[Authorize]
public class SecureController : Controller
{
    public IActionResult Index()
    {
        return View();
    }
}
 
[AllowAnonymous]
public class PublicController : Controller
{
    public IActionResult Index()
    {
        return View();
    }
}
```

## 6. Übersicht und Erläuterung zu den HTTP-Statuscodes

HTTP-Statuscodes sind standardisierte Codes, die von einem Webserver gesendet werden, um den Status einer Anfrage des Clients darzustellen. Sie sind in fünf Kategorien unterteilt:

1. **1xx (Informational)**: Anfragen wurden empfangen und der Prozess läuft weiter.
2. **2xx (Success)**: Anfragen wurden erfolgreich bearbeitet.
3. **3xx (Redirection)**: Weitere Aktionen sind erforderlich, um die Anfrage abzuschließen.
4. **4xx (Client Error)**: Anfragen enthalten Fehler oder können nicht erfüllt werden.
5. **5xx (Server Error)**: Der Server ist gescheitert, eine ansonsten gültige Anfrage zu erfüllen.

### 6.1 Unerlaubter Zugriff (4xx Statuscodes)

Die 4xx-Kategorie von Statuscodes betrifft Fehler, die durch den Client verursacht wurden. Diese sind besonders relevant für die Zugriffskontrolle und die Authentifizierung:

- **400 Bad Request**: Die Anfrage war ungültig oder nicht verarbeitbar. 
- **401 Unauthorized**: Authentifizierung ist notwendig und wurde entweder nicht durchgeführt oder ist gescheitert.
- **403 Forbidden**: Der Client hat keine Berechtigung, auf die Ressource zuzugreifen.
- **404 Not Found**: Die angeforderte Ressource wurde nicht gefunden.

#### Beispiele aus dem Backend-Projekt

- **401 Unauthorized**
  - Wird verwendet, wenn ein Benutzer versucht, sich mit falschen Anmeldedaten einzuloggen.
    ```csharp
    if (employee == null) {
        _logger.LogWarning($"Login attempt failed: User {loginDto.Username} not found.");
        return Unauthorized("User not found.");
    }
    ```

- **403 Forbidden**
  - Tritt auf, wenn ein Benutzer versucht, auf eine Ressource zuzugreifen, für die er keine Berechtigung hat.
    ```csharp
    [HttpPost("unlock/{username}")]
    [Authorize(Roles = "Administrator")]
    public async Task<IActionResult> UnlockEmployee(string username) {
        // Code to unlock an employee, only accessible by users in the 'Administrator' role
    }
    ```

- **404 Not Found**
  - Wird verwendet, wenn eine angeforderte Ressource, wie z.B. ein spezifischer Serviceauftrag, nicht gefunden wird.
    ```csharp
    var serviceOrder = await _context.ServiceOrders.FindAsync(id);
    if (serviceOrder == null) {
        _logger.LogWarning($"Service order with ID {id} not found.");
        return NotFound();
    }
    ```

Die korrekte Verwendung dieser Statuscodes ist wichtig für eine klare Kommunikation zwischen dem Client und dem Server und für die Implementierung einer effektiven Sicherheitsstrategie.

[HTTP-Statuscodes Dokumentation](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status)

## 7. Zusammenfassung und Ausblick (Fazit)

### 7.1 Wichtige Erkenntnisse und Best Practices

- **Authentifizierung und Autorisierung**: Die Bedeutung der korrekten Implementierung von Authentifizierungs- und Autorisierungsmechanismen ist entscheidend für die Sicherheit und den ordnungsgemäßen Betrieb von Webanwendungen.
  
- **Verschiedene Authentifizierungsmethoden**: Wir haben verschiedene Methoden wie Basic Authentication, API-Keys und JWTs untersucht und ihre Anwendungsfälle, Vorteile und potenziellen Risiken kennengelernt.

- **Implementierung in ASP.NET**: Die Verwendung von `[Authorize]` und `[AllowAnonymous]` Attributen in ASP.NET erlaubt eine fein abgestimmte Zugriffskontrolle auf Ressourcen und Endpunkte.

- **HTTP-Statuscodes**: Ein tiefes Verständnis der HTTP-Statuscodes und ihrer Bedeutung in Authentifizierungsszenarien ist für die Entwicklung sicherer und benutzerfreundlicher APIs unerlässlich.

### 7.2 Zukünftige Trends in der Authentifizierung

- **Erhöhte Sicherheitsanforderungen**: Mit der zunehmenden Digitalisierung steigen auch die Anforderungen an die Sicherheit. Fortschrittlichere Authentifizierungsmethoden werden entwickelt, um diesen Anforderungen gerecht zu werden.

- **Biometrische Authentifizierung**: Der Einsatz biometrischer Daten wie Fingerabdrücke oder Gesichtserkennung für die Authentifizierung wird wahrscheinlich zunehmen, da diese Methoden zusätzliche Sicherheitsebenen bieten.

- **Multi-Faktor-Authentifizierung (MFA)**: MFA wird immer häufiger eingesetzt, um die Sicherheit zu erhöhen, indem Benutzer aufgefordert werden, mehr als einen Authentifizierungsfaktor zu verwenden.

- **OAuth und OpenID Connect**: Diese Protokolle werden weiterhin eine wichtige Rolle in der sicheren Authentifizierung und Autorisierung in Webanwendungen spielen.

- **Maschinelles Lernen und KI**: Diese Technologien könnten genutzt werden, um Authentifizierungsmethoden intelligenter und benutzerfreundlicher zu gestalten.

### 7.3 Abschlussbemerkung

Die Welt der Webanwendungen und API-Entwicklung ist dynamisch und ständig im Wandel. Die Implementierung effektiver Authentifizierungs- und Autorisierungssysteme bleibt eine zentrale Herausforderung. Es ist wichtig, dass Entwickler und Unternehmen auf dem neuesten Stand der besten Praktiken und Technologien bleiben, um die Sicherheit und Funktionalität ihrer Anwendungen zu gewährleisten.
