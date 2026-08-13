use wx_context::VisibilityIndex;
use wx_db::Contact;

use crate::output::{JsonEnvelope, PagingMeta, StatsMeta};
use crate::schema::{project_session_sender, EnrichedSession};

/// Filter a fully collected result set, then rebuild paging metadata for the visible slice.
///
/// Phase 1 uses this only on relatively small list-shaped outputs (`contacts` / `sessions`),
/// where loading the current matched result set into memory is acceptable.
pub fn project_visible_envelope<T>(
    items: Vec<T>,
    limit: usize,
    offset: usize,
    stats: &StatsMeta,
    show_hidden: bool,
    should_hide: impl Fn(&T) -> bool,
) -> JsonEnvelope<T> {
    let visible: Vec<T> = if show_hidden {
        items
    } else {
        items
            .into_iter()
            .filter(|item| !should_hide(item))
            .collect()
    };

    let total = visible.len();
    let start = offset.min(total);
    let paged: Vec<T> = visible.into_iter().skip(start).take(limit).collect();
    let returned = paged.len();
    let has_more = start + returned < total;

    JsonEnvelope {
        items: paged,
        paging: PagingMeta {
            limit,
            offset,
            returned,
            has_more,
            total,
        },
        stats: StatsMeta {
            scanned: stats.scanned,
            skipped: stats.skipped,
            elapsed_ms: stats.elapsed_ms,
            shard_warnings: stats.shard_warnings.clone(),
        },
    }
}

pub fn project_contacts_envelope(
    contacts: Vec<Contact>,
    visibility: &VisibilityIndex,
    limit: usize,
    offset: usize,
    stats: &StatsMeta,
    show_hidden: bool,
) -> JsonEnvelope<Contact> {
    project_visible_envelope(contacts, limit, offset, stats, show_hidden, |contact| {
        visibility.is_hidden_talker(&contact.user_name)
    })
}

/// Filter search hits against the visibility index.
///
/// A hit is removed when its **talker** (the session it lives in) is a
/// hidden person, or its **sender** is a hidden person posting inside an
/// otherwise-visible group chat (same group-aware rule as message/session
/// projection: `is_hidden_sender_in_group`). Sender-level hiding must not
/// apply in private (non-group) chats, where the talker check already
/// covers hiding the conversation.
///
/// Currently only exercised via unit tests; production call sites use
/// `project_search_hits_raw` directly so enrichment happens after paging.
#[allow(dead_code)]
pub fn project_search_hits(
    hits: Vec<crate::schema::SearchHit>,
    visibility: &VisibilityIndex,
    show_hidden: bool,
) -> Vec<crate::schema::SearchHit> {
    project_search_hits_raw(
        hits,
        visibility,
        show_hidden,
        |hit| &hit.talker,
        |hit| &hit.sender,
    )
}

/// Filter any collection of search hits against the visibility index,
/// without requiring the hit type to already be enriched to `SearchHit`.
/// Used to filter native-FTS hits BEFORE display-name resolution so the
/// (potentially expensive) enrichment only runs on the page actually
/// returned, not the full MAX_QUERY_LIMIT window.
///
/// Same rule as [`project_search_hits`]: drop hits whose talker is hidden,
/// or whose sender is hidden inside an otherwise-visible group chat.
pub fn project_search_hits_raw<T>(
    hits: Vec<T>,
    visibility: &VisibilityIndex,
    show_hidden: bool,
    talker_of: impl Fn(&T) -> &str,
    sender_of: impl Fn(&T) -> &str,
) -> Vec<T> {
    if show_hidden {
        return hits;
    }
    hits.into_iter()
        .filter(|hit| {
            let talker = talker_of(hit);
            !visibility.is_hidden_talker(talker)
                && !visibility.is_hidden_sender_in_group(talker, sender_of(hit))
        })
        .collect()
}

#[allow(dead_code)]
pub fn project_sessions_envelope<T>(
    sessions: Vec<T>,
    visibility: &VisibilityIndex,
    limit: usize,
    offset: usize,
    stats: &StatsMeta,
    show_hidden: bool,
    talker_of: impl Fn(&T) -> &str,
) -> JsonEnvelope<T> {
    project_visible_envelope(sessions, limit, offset, stats, show_hidden, |session| {
        visibility.is_hidden_talker(talker_of(session))
    })
}

/// Phase 2: project_sessions_envelope with sender-level redaction for EnrichedSession.
///
/// After talker-level filtering, applies `project_session_sender` to redact
/// hidden senders in group chat session summaries.
pub fn project_sessions_envelope_enriched(
    sessions: Vec<EnrichedSession>,
    visibility: &VisibilityIndex,
    limit: usize,
    offset: usize,
    stats: &StatsMeta,
    show_hidden: bool,
) -> JsonEnvelope<EnrichedSession> {
    let mut envelope = project_visible_envelope(
        sessions,
        limit,
        offset,
        stats,
        show_hidden,
        |session: &EnrichedSession| visibility.is_hidden_talker(&session.session.username),
    );

    if !show_hidden {
        for session in &mut envelope.items {
            project_session_sender(session, visibility);
        }
    }

    envelope
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stats_meta(scanned: usize) -> StatsMeta {
        StatsMeta {
            scanned,
            skipped: 0,
            elapsed_ms: Some(1),
            shard_warnings: Vec::new(),
        }
    }

    #[test]
    fn visible_projection_rebuilds_total_and_offset_on_filtered_set() {
        let envelope = project_visible_envelope(
            vec!["wxid_a", "wxid_hidden", "wxid_b"],
            1,
            1,
            &stats_meta(3),
            false,
            |talker| *talker == "wxid_hidden",
        );

        assert_eq!(envelope.items, vec!["wxid_b"]);
        assert_eq!(envelope.paging.total, 2);
        assert_eq!(envelope.paging.returned, 1);
        assert_eq!(envelope.paging.offset, 1);
        assert!(!envelope.paging.has_more);
        assert_eq!(envelope.stats.scanned, 3);
    }

    fn search_hit(sender: &str, talker: &str) -> crate::schema::SearchHit {
        crate::schema::SearchHit {
            server_id: 1,
            talker: talker.to_string(),
            talker_display_name: talker.to_string(),
            sender: sender.to_string(),
            sender_display_name: sender.to_string(),
            direction: wx_context::Direction::Incoming,
            create_time: 1,
            sort_seq: 1,
            msg_type: 1,
            sub_type: 0,
            snippet: "snippet".to_string(),
            hit_type: "Message".to_string(),
        }
    }

    #[test]
    fn empty_sender_is_never_treated_as_hidden() {
        // A hit whose sender failed to resolve (empty string) must not be
        // filtered just because the hidden set exists.
        let hidden = wx_context::VisibilityIndex::build(
            &["wxid_spam".to_string()],
            &[],
            &wx_context::ContactResolver::empty(),
        );
        let hits = vec![
            // Empty sender in a private (non-group) chat: must survive.
            search_hit("", "wxid_alice"),
            // Hidden sender, but talker is a private chat (not a group) —
            // sender-level hiding is group-only, so this must survive too.
            search_hit("wxid_spam", "wxid_alice"),
            // Talker itself is hidden: filtered regardless of sender.
            search_hit("wxid_bob", "wxid_spam"),
        ];
        let visible = project_search_hits(hits, &hidden, false);
        assert_eq!(visible.len(), 2, "only the hidden-talker hit is dropped");
        assert_eq!(visible[0].sender, "");
        assert_eq!(visible[0].talker, "wxid_alice");
        assert_eq!(visible[1].sender, "wxid_spam");
        assert_eq!(visible[1].talker, "wxid_alice");
    }

    #[test]
    fn hidden_sender_in_visible_group_is_filtered() {
        // Group-aware sender hiding: a hidden person posting inside an
        // otherwise-visible group chat is filtered at the sender level,
        // mirroring is_hidden_sender_in_group used by message/session
        // projection.
        let hidden = wx_context::VisibilityIndex::build(
            &["wxid_spam".to_string()],
            &[],
            &wx_context::ContactResolver::empty(),
        );
        let hits = vec![
            search_hit("wxid_spam", "group1@chatroom"),
            search_hit("wxid_visible", "group1@chatroom"),
        ];
        let visible = project_search_hits(hits, &hidden, false);
        assert_eq!(visible.len(), 1);
        assert_eq!(visible[0].sender, "wxid_visible");
    }

    #[test]
    fn show_hidden_bypasses_filtering() {
        let envelope = project_visible_envelope(
            vec!["wxid_a", "wxid_hidden", "wxid_b"],
            3,
            0,
            &stats_meta(3),
            true,
            |talker| *talker == "wxid_hidden",
        );

        assert_eq!(envelope.items, vec!["wxid_a", "wxid_hidden", "wxid_b"]);
        assert_eq!(envelope.paging.total, 3);
        assert_eq!(envelope.paging.returned, 3);
        assert!(!envelope.paging.has_more);
    }
}
