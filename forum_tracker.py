
from __future__ import annotations

import re
import threading
import time
import requests
from bs4 import BeautifulSoup
from typing import List, Dict, Optional
from urllib.parse import urljoin
from .utils import (
    normalize_url, detect_type,
    extract_thread_id, extract_post_id_from_article,
    log_info, log_error
)
from .storage import list_all_tracks, update_last
import traceback
import datetime


try:
    from config import XF_USER, XF_SESSION, XF_TFA_TRUST, FORUM_BASE, POLL_INTERVAL_SEC, XF_CSRF
except Exception:
    XF_USER = ""
    XF_SESSION = ""
    XF_TFA_TRUST = ""
    FORUM_BASE = ""
    XF_CSRF = ""
    POLL_INTERVAL_SEC = 20

DEFAULT_POLL = 20
try:
    POLL = int(POLL_INTERVAL_SEC)
    if POLL <= 0:
        POLL = DEFAULT_POLL
except Exception:
    POLL = DEFAULT_POLL


def debug(msg: str):
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        log_info(str(msg))
    except Exception:
        print(f"[{now}] [DEBUG] {msg}")


def warn(msg: str):
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        log_error(str(msg))
    except Exception:
        print(f"[{now}] [WARNING] {msg}")



def build_cookies() -> dict:
    """Return cookies dict (for requests)."""
    return {
        "xf_user": globals().get("XF_USER", XF_USER) or "",
        "xf_session": globals().get("XF_SESSION", XF_SESSION) or "",
        "xf_tfa_trust": globals().get("XF_TFA_TRUST", XF_TFA_TRUST) or "",
        "xf_csrf": globals().get("XF_CSRF", XF_CSRF) or "",
    }




def parse_thread_posts(html: str, page_url: str, session=None) -> List[Dict]:
    """
    Улучшенный парсер постов с поддержкой ПОСЛЕДНЕЙ страницы темы.
    """
    soup = BeautifulSoup(html or "", "html.parser")

 
    last_page = 1
    pages = soup.select(".pageNav-page")
    for p in pages:
        try:
            num = int(p.get_text(strip=True))
            last_page = max(last_page, num)
        except:
            pass

    
    if last_page > 1 and session:
        if page_url.endswith("/"):
            url_last = f"{page_url}page-{last_page}/"
        else:
            url_last = f"{page_url}/page-{last_page}/"

        try:
            r = session.get(url_last, timeout=15)
            if r.status_code == 200:
                html = r.text
                soup = BeautifulSoup(html or "", "html.parser")
        except Exception as e:
            warn(f"Error loading last page: {e}")


  
    posts_nodes = soup.select("article.message-body.js-selectToQuote")
    if not posts_nodes:
        posts_nodes = soup.select("article[data-post-id], article[id^='js-post-']")

    out: List[Dict] = []

    for msg in posts_nodes:
        try:
            pid = (
                msg.get("data-lb-id")
                or msg.get("data-id")
                or msg.get("data-post-id")
                or ""
            )

            if not pid:
                art = msg.find_parent("article")
                if art:
                    pid = extract_post_id_from_article(str(art))

            pid = str(pid)

            user = (
                msg.find_previous("a", class_="username")
                or msg.find_previous("h4", class_="message-name")
                or msg.find_previous("span", class_="username")
            )
            author = user.get_text(strip=True) if user else "Неизвестно"

            t = msg.find_previous("time")
            date = t.get("datetime") if t else ""

            body = (
                msg.select_one("div.bbWrapper")
                or msg.select_one("div.message-userContent.lbContainer.js-lbContainer")
                or msg.select_one("div.message-userContent")
            )

            text = body.get_text("\n", strip=True) if body else msg.get_text("\n", strip=True)
            text = re.sub(r"\n{2,}", "\n", text).strip()

            link = page_url.rstrip("/") + f"#post-{pid}"

            out.append({
                "id": pid,
                "author": author,
                "date": date,
                "text": text,
                "link": link,
            })

        except Exception as e:
            warn(f"parse_thread_posts error: {e}")
            continue

    return out



def parse_forum_topics(html: str, base_url: str) -> List[Dict]:
    """
    Надёжный парсер тем MatRP. Возвращает список словарей с полями:
      tid, title, author, url, pinned, created
    """
    soup = BeautifulSoup(html or "", "html.parser")
    topics: List[Dict] = []

    blocks = soup.select(".structItem")
    if not blocks:
        return topics

    seen = set()

    for it in blocks:
        try:
            tid = None
            classes = it.get("class", []) or []

            # TID из класса js-threadListItem-XXXXX
            for c in classes:
                if isinstance(c, str) and c.startswith("js-threadListItem-"):
                    tid = c.replace("js-threadListItem-", "")
                    break

            # fallback через ссылку в title блоке
            title_a = it.select_one(".structItem-title a[data-preview-url], .structItem-title a[href]")
            if not tid and title_a:
                href_tmp = title_a.get("href", "")
                m = re.search(r"\.(\d+)/?$", href_tmp)
                if not m:
                    m = re.search(r"/threads/[^/]+\.(\d+)/?", href_tmp)
                if m:
                    tid = m.group(1)

            if not tid:
                continue

            tid = int(tid)
            if tid in seen:
                continue
            seen.add(tid)

            # Заголовок: берем превью-ссылку (реальный заголовок), иначе labelLink
            title_el = it.select_one(".structItem-title a[data-preview-url]") or \
                       it.select_one(".structItem-title a.labelLink") or \
                       it.select_one(".structItem-title a[href]")

            if not title_el:
                continue

            title = title_el.get_text(" ", strip=True)
            href = title_el.get("href", "") or ""

            # Убираем prefix_id
            href = href.split("&prefix_id")[0].split("?prefix_id")[0]

            # Абсолютный URL
            if href.startswith("http"):
                url = href
            else:
                root = base_url.split("/index.php")[0]
                url = urljoin(root + "/", href.lstrip("/"))

            # Нормализуем в формат threads/<slug>.<tid>/
            m_full = re.search(r"/threads/([^/]+)\.(\d+)/?", url)
            if m_full:
                slug = m_full.group(1)
                tid = int(m_full.group(2))
                url = f"https://forum.matrp.ru/threads/{slug}.{tid}/"
            else:
                url = f"https://forum.matrp.ru/threads/topic.{tid}/"

         
            auth_el = it.select_one(".structItem-minor .username, a.username")
            author = auth_el.get_text(strip=True) if auth_el else "Unknown"

          
            pinned = any("pinned" in c or "sticky" in c or "structItem--pinned" in c for c in classes)

            
            time_el = it.select_one("time")
            created = time_el.get("datetime", "").strip() if time_el else ""

            topics.append({
                "tid": tid,
                "title": title,
                "author": author,
                "url": url,
                "pinned": pinned,
                "created": created
            })
        except Exception:
            continue

    return topics





class ForumTracker:
   

    def __init__(self, *args):
        self.interval = POLL
        self._running = False
        self._keepalive_running = True
        self.vk = None
        self.user_id = None  # Добавляем user_id для привязки к пользователю

        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "Accept": "*/*",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate",
            "Referer": FORUM_BASE,
            "Connection": "Keep-alive"
        })

        # Новый вариант для инициализации через auth_manager
        if len(args) == 1 and isinstance(args[0], dict):
            # args[0] - словарь с данными пользователя
            user_data = args[0]
            self.user_id = user_data.get("user_id")
            
            # Устанавливаем куки из данных пользователя
            if user_data.get("xf_user"):
                self.session.cookies.set("xf_user", user_data["xf_user"])
            if user_data.get("xf_tfa_trust"):
                self.session.cookies.set("xf_tfa_trust", user_data["xf_tfa_trust"])
            if user_data.get("xf_session"):
                self.session.cookies.set("xf_session", user_data["xf_session"])
            if user_data.get("xf_csrf"):
                self.session.cookies.set("xf_csrf", user_data["xf_csrf"])

     
        if len(args) == 1:
            self.vk = args[0]
     
            for k, v in build_cookies().items():
                if v:
                    try:
                        self.session.cookies.set(k, v)
                    except Exception:
                        try:
                            domain = FORUM_BASE.replace("https://", "").replace("http://", "").split("/")[0]
                            self.session.cookies.set(k, v, domain=domain)
                        except Exception:
                            pass


        elif len(args) >= 4:
            xf_user, xf_tfa_trust, xf_session, vk = args[:4]
            self.vk = vk
            globals()["XF_USER"] = xf_user
            globals()["XF_TFA_TRUST"] = xf_tfa_trust
            globals()["XF_SESSION"] = xf_session
         
            domain = ""
            try:
                domain = FORUM_BASE.replace("https://", "").replace("http://", "").split("/")[0]
            except Exception:
                domain = None
            if xf_user:
                try:
                    self.session.cookies.set("xf_user", xf_user, domain=domain)
                except Exception:
                    self.session.cookies.set("xf_user", xf_user)
            if xf_tfa_trust:
                try:
                    self.session.cookies.set("xf_tfa_trust", xf_tfa_trust, domain=domain)
                except Exception:
                    self.session.cookies.set("xf_tfa_trust", xf_tfa_trust)
            if xf_session:
                try:
                    self.session.cookies.set("xf_session", xf_session, domain=domain)
                except Exception:
                    self.session.cookies.set("xf_session", xf_session)
        else:
            raise TypeError("ForumTracker expected (vk) or (XF_USER, XF_TFA_TRUST, XF_SESSION, vk)")

    
        if hasattr(self.vk, "set_trigger"):
            try:
                self.vk.set_trigger(self.force_check)
            except Exception:
                pass

    
        threading.Thread(target=self._keepalive_loop, daemon=True).start()

    # -----------------------------------------------------------------
    # Утилиты доступа к сети через session
    # -----------------------------------------------------------------
    def fetch_html(self, url: str, timeout: int = 15) -> str:
        """
        Загрузить HTML используя self.session (с куками).
        """
        if not url:
            return ""

        try:
            url = normalize_url(url)
        except Exception:
            pass

        debug(f"[FETCH] GET {url}")
        try:
            # ФИКС ДЛЯ UNICODE: чистим заголовки от русских символов
            from urllib.parse import quote, urlparse, urlunparse
            
            # Декодируем если есть процентное кодирование
            import urllib.parse as up
            decoded_url = up.unquote(url)
            
            # Разбираем URL
            parsed = urlparse(decoded_url)
            
            # Кодируем путь если нужно
            if any(ord(c) > 127 for c in parsed.path):
                encoded_path = quote(parsed.path, safe='/')
            else:
                encoded_path = parsed.path
                
            # Собираем безопасный URL
            safe_url = urlunparse((
                parsed.scheme,
                parsed.netloc,
                encoded_path,
                parsed.params,
                parsed.query,
                parsed.fragment
            ))
            
            # Делаем запрос
            r = self.session.get(safe_url, timeout=timeout, allow_redirects=True)
            debug(f"[FETCH] {safe_url} -> {getattr(r, 'status_code', 'ERR')}")
            
            if getattr(r, "status_code", 0) == 200:
                # Явно указываем кодировку
                if r.encoding is None or r.encoding == 'ISO-8859-1':
                    r.encoding = 'utf-8'
                return r.text
            warn(f"HTTP {getattr(r, 'status_code', 'ERR')} for {safe_url}")
            return ""
            
        except UnicodeEncodeError as e:
            # ФАЛЛБЭК: используем urllib напрямую
            warn(f"Unicode encode error: {e}")
            try:
                import urllib.request
                import http.cookiejar
                
                # Создаем opener с куками
                cj = http.cookiejar.CookieJar()
                opener = urllib.request.build_opener(
                    urllib.request.HTTPCookieProcessor(cj)
                )
                
                # Добавляем куки из сессии
                for cookie in self.session.cookies:
                    c = http.cookiejar.Cookie(
                        version=0,
                        name=cookie.name,
                        value=cookie.value,
                        port=None,
                        port_specified=False,
                        domain=cookie.domain,
                        domain_specified=bool(cookie.domain),
                        domain_initial_dot=cookie.domain.startswith('.'),
                        path=cookie.path,
                        path_specified=bool(cookie.path),
                        secure=cookie.secure,
                        expires=cookie.expires,
                        discard=False,
                        comment=None,
                        comment_url=None,
                        rest={'HttpOnly': cookie.has_nonstandard_attr('HttpOnly')},
                        rfc2109=False
                    )
                    cj.set_cookie(c)
                
                # Устанавливаем заголовки
                req = urllib.request.Request(
                    url,
                    headers={
                        'User-Agent': 'Mozilla/5.0',
                        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                        'Accept-Language': 'en-US,en;q=0.5'
                    }
                )
                
                response = opener.open(req, timeout=timeout)
                html = response.read().decode('utf-8', errors='ignore')
                return html
                
            except Exception as fallback_error:
                warn(f"Fallback also failed: {fallback_error}")
                return ""
                
        except Exception as e:
            warn(f"fetch_html error: {e}")
            return ""

    def get(self, url: str, **kwargs):
        try:
            # ФИКС: применяем ту же логику для get
            from urllib.parse import quote, urlparse, urlunparse
            parsed = urlparse(url)
            if any(ord(c) > 127 for c in parsed.path):
                encoded_path = quote(parsed.path, safe='/')
                url = urlunparse((
                    parsed.scheme,
                    parsed.netloc,
                    encoded_path,
                    parsed.params,
                    parsed.query,
                    parsed.fragment
                ))
            return self.session.get(url, **kwargs)
        except Exception as e:
            warn(f"session.get error: {e}")
            raise

    def react_to_post(self, post_url: str, reaction_id: int):
        """
        Поставить реакцию на пост в форуме.
        Возвращает (ok: bool, message: str)
        """
        try:
            # 1. Вытаскиваем ID поста из URL
            import re
            m = re.search(r'post-(\d+)', post_url)
            if not m:
                return False, "Не найден ID поста в URL"
            
            post_id = m.group(1)
            
            # 2. Сначала получаем страницу поста, чтобы извлечь _xfToken
            debug(f"[REACT] Getting page for post {post_id}...")
            post_page_url = f"{FORUM_BASE}/index.php?posts/{post_id}/"
            
            r = self.session.get(
                post_page_url,
                headers={"referer": FORUM_BASE},
                timeout=15
            )
            
            if r.status_code != 200:
                return False, f"Не удалось загрузить страницу поста: HTTP {r.status_code}"
            
            # 3. Ищем _xfToken в HTML
            import re
            xf_token_match = re.search(r'data-csrf="([^"]+)"', r.text)
            if not xf_token_match:
                xf_token_match = re.search(r'_xfToken" value="([^"]+)"', r.text)
            if not xf_token_match:
                xf_token_match = re.search(r'data-xf-csrf="([^"]+)"', r.text)
            
            if not xf_token_match:
                return False, "Не найден _xfToken на странице"
            
            _xfToken = xf_token_match.group(1)
            debug(f"[REACT] Found _xfToken: {_xfToken[:20]}...")
            
            # 4. Формируем URL для отправки реакции
            react_url = f"{FORUM_BASE}/index.php?posts/{post_id}/react"
            
            # 5. Подготавливаем данные для POST
            data = {
                "reaction_id": reaction_id,
                "_xfToken": _xfToken,
                "_xfRequestUri": f"/index.php?posts/{post_id}/",
                "_xfWithData": "1",
                "_xfResponseType": "json"
            }
            
            headers = {
                "referer": post_page_url,
                "x-requested-with": "XMLHttpRequest",
                "content-type": "application/x-www-form-urlencoded; charset=UTF-8",
                "accept": "application/json, text/javascript, */*; q=0.01",
                "origin": FORUM_BASE
            }
            
            debug(f"[REACT] POST to {react_url} with reaction_id={reaction_id}")
            
            # 6. Отправляем POST-запрос
            r = self.session.post(
                react_url,
                data=data,
                headers=headers,
                timeout=15
            )
            
            debug(f"[REACT] Response status: {r.status_code}")
            debug(f"[REACT] Response headers: {dict(r.headers)}")
            debug(f"[REACT] Response body (first 500): {r.text[:500]}")
            
            # 7. Проверяем результат
            if r.status_code == 200:
                try:
                    json_resp = r.json()
                    if json_resp.get("status") == "ok":
                        return True, "✅ Реакция успешно поставлена"
                    else:
                        error_msg = json_resp.get("error", "Неизвестная ошибка")
                        return False, f"❌ Ошибка от сервера: {error_msg}"
                except ValueError:
                    # Если не JSON, но 200 - скорее всего успех
                    if "success" in r.text.lower() or "ок" in r.text.lower():
                        return True, "✅ Реакция успешно поставлена"
                    return False, "❌ Не удалось разобрать ответ сервера"
            
            elif r.status_code == 403:
                return False, "❌ Ошибка 403: Доступ запрещен. Проверьте авторизацию."
            elif r.status_code == 404:
                return False, f"❌ Ошибка 404: Пост {post_id} не найден."
            else:
                return False, f"❌ HTTP ошибка {r.status_code}: {r.text[:200]}"
                
        except requests.exceptions.Timeout:
            return False, "❌ Таймаут при отправке реакции"
        except requests.exceptions.ConnectionError:
            return False, "❌ Ошибка соединения с форумом"
        except Exception as e:
            debug(f"[REACT] Exception: {e}")
            import traceback
            debug(f"[REACT] Traceback: {traceback.format_exc()}")
            return False, f"❌ Неизвестная ошибка: {str(e)[:100]}"

    # --- API control ---
    def start(self):
        if self._running:
            return
        self._running = True
        threading.Thread(target=self._loop, daemon=True).start()
        try:
            log_info(f"ForumTracker started (interval={self.interval})")
        except Exception:
            debug(f"ForumTracker started (interval={self.interval})")

    def stop(self):
        self._running = False
        self._keepalive_running = False
        try:
            log_info("ForumTracker stopped")
        except Exception:
            debug("ForumTracker stopped")

    def force_check(self):
        threading.Thread(target=self.check_all, daemon=True).start()

    def _loop(self):
        while self._running:
            try:
                self.check_all()
            except Exception as e:
                warn(f"loop error: {e}")
                traceback.print_exc()
            time.sleep(self.interval)

    def check_all(self):
        rows = list_all_tracks()
        if not rows:
            return
        by_url = {}
        for peer_id, url, typ, last_id in rows:
            by_url.setdefault(url, []).append((peer_id, typ, last_id))
        for url, subs in by_url.items():
            try:
                self._process_url(url, subs)
            except Exception as e:
                warn(f"_process_url error for {url}: {e}")
                traceback.print_exc()


    def _process_url(self, url: str, subscribers):
        url = normalize_url(url)

        if not url.startswith(FORUM_BASE):
            debug(f"[process] skipping non-forum url: {url}")
            return

        html = self.fetch_html(url)
        if not html:
            warn(f"failed to fetch: {url}")
            return

        typ = detect_type(url)

        
        if typ == "thread":
            posts = parse_thread_posts(html, url, self.session)
            if not posts:
                return

            newest = posts[-1]
            try:
                newest_id = int(newest["id"])
            except Exception:
             
                newest_id = newest["id"]

            for peer_id, _, last in subscribers:
                try:
                    last_id = int(last) if last is not None else 0
                except Exception:
                
                    last_id = 0

                send_msg = False
         
                if isinstance(newest_id, int) and isinstance(last_id, int):
                    send_msg = newest_id > last_id
                else:
           
                    send_msg = str(newest["id"]) != str(last)

                if send_msg:
                    msg = (
                        f"📝 Новый пост\n"
                        f"👤 {newest['author']}  •  {newest['date']}\n\n"
                        f"{(newest['text'][:1500] + '...') if len(newest['text'])>1500 else newest['text']}\n\n"
                        f"🔗 {newest['link']}"
                    )
                    try:
                        self.vk.send(peer_id, msg)
                    except Exception as e:
                        warn(f"vk send error (thread): {e}")

                    try:
                        update_last(peer_id, url, str(newest_id))
                    except Exception as e:
                        warn(f"update_last error (thread): {e}")

            return

        
        if typ == "forum":
            topics = parse_forum_topics(html, url)
            if not topics:
                return


            sortable = []
            for t in topics:
                created = t.get("created") or ""
                try:
                    tid_i = int(t.get("tid", 0))
                except Exception:
                    tid_i = 0
                sortable.append((created, tid_i, t))


                sortable.sort(key=lambda x: (x[0] or "", x[1]))

  
                last_created, last_tid, last_topic = sortable[-1][0], sortable[-1][1], sortable[-1][2]

                for peer_id, _, last_saved in subscribers:
                    saved_tid = 0
                    saved_date = ""

                    if last_saved and ";;" in str(last_saved):
                        parts = str(last_saved).split(";;", 1)
                        try:
                           saved_tid = int(parts[0])
                        except Exception:
                           saved_tid = 0
                        saved_date = parts[1]
                    else:
                        try:
                            saved_tid = int(last_saved)
                        except Exception:
                            saved_tid = 0

                    is_new = False


                    if last_created and saved_date:
                        try:
       
                            if last_created > saved_date:
                                is_new = True
                        except Exception:
                            pass


                    if not is_new:
                        if last_tid > saved_tid:
                            is_new = True

                    if not is_new:
                        continue

  
                    msg = (
                        "🆕 Новая тема в разделе:\n\n"
                        f"📄 {last_topic.get('title')}\n"
                        f"👤 {last_topic.get('author')}\n"
                        f"⏱ {last_created}\n"
                        f"🔗 {last_topic.get('url')}"
                    )
                    try:
                        self.vk.send(peer_id, msg)
                    except Exception as e:
                        warn(f"vk send error (forum): {e}")

      
                    try:
                        update_last(peer_id, url, f"{last_tid};;{last_created}")
                    except Exception as e:
                        warn(f"update_last error (forum): {e}")

                return
        debug(f"[process] unknown type for {url}: {typ}")

 
    def manual_fetch_posts(self, url: str) -> List[Dict]:
        url = normalize_url(url)
        debug(f"[manual_fetch_posts] URL = {url}")
        debug(f"[manual_fetch_posts] Cookies = {build_cookies()}")
        if not url.startswith(FORUM_BASE):
            raise ValueError("URL outside FORUM_BASE")
        html = self.fetch_html(url)
        if not html:
            raise RuntimeError("Failed to fetch page (check cookies)")
        posts = parse_thread_posts(html, url, self.session)
        debug(f"[manual_fetch_posts] Parsed posts = {len(posts)}")
        return posts

    def debug_reply_form(self, url: str) -> str:
        url = normalize_url(url)
        html = self.fetch_html(url)
        cookies = build_cookies()
        if not html:
            return "❌ Не удалось загрузить страницу\nCookies: " + str(cookies)
        soup = BeautifulSoup(html, "html.parser")
        form = (
            soup.select_one("form[action*='add-reply']") or
            soup.select_one("form.js-quickReply") or
            soup.select_one("form[data-xf-init*='quick-reply']") or
            soup.select_one("form[action*='post']")
        )
        textarea = None
        if form:
            textarea = (
                form.select_one("textarea[name='message_html']") or
                form.select_one("textarea[name='message']") or
                form.select_one("textarea")
            )
        logged = (
            ("logout" in html.lower()) or
            ("выйти" in html.lower()) or
            ("data-xf-init=\"member-tooltip\"" in html)
        )
        return (
            "🔍 DEBUG REPLY FORM\n"
            f"✔ Logged in: {logged}\n"
            f"✔ Cookies OK: {bool(cookies)}\n"
            f"✔ Form found: {bool(form)}\n"
            f"✔ Textarea found: {bool(textarea)}\n"
            f"✔ Textarea name: {textarea.get('name') if textarea else '—'}\n"
            f"✔ Action: {form.get('action') if form else '—'}\n"
            "-----------------------------------\n"
            "Cookies:\n"
            f"{cookies}\n"
            "-----------------------------------\n"
            "HTML снизу страницы:\n"
            + html[-2000:]
        )

    def fetch_latest_post_id(self, url: str) -> Optional[str]:
        """Возвращает id самого свежего поста на thread-странице или None."""
        try:
            html = self.fetch_html(url)
            if not html:
                return None
            posts = parse_thread_posts(html, url, self.session)
            if not posts:
                return None
            return str(posts[-1]["id"]) if posts else None
        except Exception:
            return None

    def post_message(self, url: str, message: str) -> Dict:
        debug(f"[POST] Sending to: {url}")
        url = normalize_url(url)
        if not url.startswith(FORUM_BASE):
            return {"ok": False, "error": "URL outside FORUM_BASE"}

        try:
            debug(f"[POST] Cookies: xf_user={XF_USER[:6]}..., xf_session={XF_SESSION[:6]}..., xf_tfa={XF_TFA_TRUST[:6]}...")
        except Exception:
            debug("[POST] Cookies: (not available)")

        html = self.fetch_html(url)
        if not html:
            return {"ok": False, "error": "Cannot fetch page"}

        soup = BeautifulSoup(html, "html.parser")

        form = (
            soup.select_one("form[action*='add-reply']") or
            soup.select_one("form.js-quickReply") or
            soup.select_one("form[data-xf-init*='quick-reply']") or
            soup.select_one("form[action*='post']")
        )
        debug(f"[POST] Form found: {bool(form)}")
        if not form:
            return {"ok": False, "error": "Reply form not found"}

        action = form.get("action") or url
        if not action.startswith("http"):
            action = urljoin(FORUM_BASE, action.lstrip("/"))
        debug(f"[POST] Form action: {action}")

        payload: Dict[str, str] = {}
        for inp in form.select("input"):
            name = inp.get("name")
            if name:
                payload[name] = inp.get("value", "") or ""

        payload["_xfWithData"] = "1"
        payload["_xfResponseType"] = "json"

        if not payload.get("_xfToken"):
            t = soup.find("input", {"name": "_xfToken"})
            if t:
                payload["_xfToken"] = t.get("value", "")

        try:
            payload["_xfRequestUri"] = url.replace(FORUM_BASE, "") or "/"
        except Exception:
            payload["_xfRequestUri"] = "/"

        textarea = (
            form.select_one("textarea[name='message_html']") or
            form.select_one("textarea[name='message']") or
            form.select_one("textarea[data-original-name='message']") or
            form.select_one("textarea")
        )
        debug(f"[POST] Textarea found: {bool(textarea)}")
        if not textarea:
            return {"ok": False, "error": "Textarea not found"}

        textarea_name = textarea.get("name") or "message"
        html_msg = f"<p>{message}</p>"

        payload[textarea_name] = html_msg
        payload["message"] = message
        payload["message_html"] = html_msg

        headers = {
            "User-Agent": "Mozilla/5.0",
            "Referer": url,
            "X-Requested-With": "XMLHttpRequest",
            "Accept": "*/*",
        }

        normal_error = None
        multipart_error = None

        debug("[POST] Trying normal mode...")
        try:
            r = self.session.post(action, data=payload, headers=headers, timeout=25)
            debug(f"[POST] Normal POST code: {getattr(r, 'status_code', 'ERR')}")
            if getattr(r, "status_code", 0) in (200, 204, 302):
                time.sleep(1)
                check = self.fetch_html(url)
                if check and message.split()[0] in check:
                    return {"ok": True, "response": "posted (normal)"}
            normal_error = f"HTTP {getattr(r, 'status_code', 'ERR')}"
        except Exception as e:
            normal_error = str(e)
        warn(f"[POST] Normal failed: {normal_error}")

        debug("[POST] Trying multipart...")
        multipart = {
            textarea_name: (None, html_msg, "text/html"),
            "message": (None, message),
            "message_html": (None, html_msg)
        }
        for k, v in payload.items():
            if k not in multipart:
                multipart[k] = (None, v if v is not None else "")

        try:
            r = self.session.post(action, files=multipart, headers=headers, timeout=25)
            debug(f"[POST] Multipart code: {getattr(r, 'status_code', 'ERR')}")
            if getattr(r, "status_code", 0) in (200, 204, 302):
                time.sleep(1)
                check = self.fetch_html(url)
                if check and message.split()[0] in check:
                    return {"ok": True, "response": "posted (multipart)"}
            multipart_error = f"HTTP {getattr(r, 'status_code', 'ERR')}"
        except Exception as e:
            multipart_error = str(e)
        warn(f"[POST] Multipart failed: {multipart_error}")

        return {
            "ok": False,
            "error": "Post failed",
            "normal_err": normal_error,
            "multipart_err": multipart_error
        }

    def check_cookies(self) -> Dict:
        test_url = (FORUM_BASE.rstrip("/") + "/index.php") if FORUM_BASE else "/"
        headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/122.0.0.0 Safari/537.36"
            )
        }
        cookies = build_cookies()
        try:
            r = self.session.get(test_url, headers=headers, cookies=cookies, timeout=15)
            html = r.text or ""
            logged = ("logout" in html.lower()) or ("выйти" in html.lower()) or ('data-logged-in="true"' in html)
            return {
                "ok": True,
                "logged_in": bool(logged),
                "status": getattr(r, "status_code", None),
                "cookies_sent": cookies,
                "html_sample": html[:500]
            }
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def _keepalive_loop(self):
        while self._keepalive_running:
            try:
                self.fetch_html(FORUM_BASE)
            except Exception as e:
                warn(f"keepalive error: {e}")
            time.sleep(max(60, self.interval * 3))

    def debug_forum(self, url: str) -> str:
        out_lines = []
        try:
            url = normalize_url(url)
        except Exception:
            pass

        out_lines.append(f"🔍 DEBUG FORUM\nURL: {url}\n")

        try:
            html = self.fetch_html(url)
            if not html:
                return "❌ Не удалось загрузить страницу. Проверь cookies / FORUM_BASE."
        except Exception as e:
            return f"❌ Ошибка fetch_html: {e}"

        soup = BeautifulSoup(html, "html.parser")

        selectors = [
            ".uix_stickyContainerOuter .structItem",
            ".uix_stickyContainerInner .structItem",
            ".structItemContainer-group .structItem",
            ".block-body .structItem",
            ".structItem",
            ".structItem--thread",
            ".structItem.js-threadListItem"
        ]

        out_lines.append("Селекторы и найденные количества:")
        for sel in selectors:
            try:
                nodes = soup.select(sel)
                out_lines.append(f"  {sel} -> {len(nodes)}")
            except Exception as e:
                out_lines.append(f"  {sel} -> ERR ({e})")

        try:
            all_items = soup.select(".structItem")
            out_lines.append(f"\nВсего .structItem: {len(all_items)}")
            for i, it in enumerate(all_items[:3]):
                snippet = str(it)[:1200].replace("\n", " ")
                out_lines.append(f"\n--- structItem #{i+1} ---\n{snippet}\n")
        except Exception as e:
            out_lines.append(f"\nОшибка при выводе structItem: {e}")

        try:
            parsed = parse_forum_topics(html, url)
            out_lines.append(f"\nparse_forum_topics -> найдено {len(parsed)} элементов:")
            for p in parsed[:10]:
                out_lines.append(
                    f"  tid={p.get('tid')} | {p.get('title')[:70]} | {p.get('author')} | pinned={p.get('pinned')}"
                )
        except Exception as e:
            out_lines.append(f"\nparse_forum_topics error: {e}")

        try:
            area = (
                soup.select_one(".structItemContainer-group")
                or soup.select_one(".block-body")
                or soup.select_one(".p-body")
            )
            if area:
                out_lines.append("\n--- HTML блока тем (2000 chars) ---")
                out_lines.append(str(area)[:2000].replace("\n", " "))
            else:
                out_lines.append("\nНе найден основной контейнер.")
        except Exception as e:
            out_lines.append(f"\nОшибка при выводе блока тем: {e}")

        out_lines.append("\nПодсказки:")
        out_lines.append(" • Если селекторы возвращают 0 — форум грузит темы через JS/Ajax.")
        out_lines.append(" • Если structItem есть — скинь первый structItem, я напишу точный парсер.")
        out_lines.append(" • Если parse пустой — не совпадают классы MatRP.")

        return "\n".join(out_lines)


def stay_online_loop():
    """
    Simple loop to ping FORUM_BASE every 3 minutes to keep session alive.
    """
    cookies = build_cookies()
    url = FORUM_BASE or ""
    if not url:
        print("[ONLINE] FORUM_BASE not configured")
        return
    while True:
        try:
            requests.get(url, cookies=cookies, timeout=10)
            print("[ONLINE] ping OK")
        except Exception as e:
            print("[ONLINE ERROR]", e)
        time.sleep(180)
