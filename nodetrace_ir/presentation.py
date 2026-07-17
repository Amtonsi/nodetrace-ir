from __future__ import annotations


ENTITY_GROUPS = {
    "file": "file",
    "artifact": "file",
    "zone_identifier": "file",
    "alternate_data_stream": "file",
    "module": "file",
    "authenticode_signature": "file",
    "delivery_source": "source",
    "download_origin": "source",
    "removable_media": "source",
    "process": "process",
    "user": "user",
    "host": "host",
    "registry": "persistence",
    "run_key_value": "persistence",
    "service": "persistence",
    "driver": "persistence",
    "autorun": "persistence",
    "scheduled_task": "persistence",
    "startup": "persistence",
    "startup_item": "persistence",
    "network": "network",
    "connection": "network",
    "network_connection": "network",
    "network_endpoint": "network",
    "dns_cache_record": "network",
    "ip": "network",
    "domain": "network",
    "event": "event",
    "windows_event": "event",
    "powershell_script": "event",
    "alert": "alert",
    "malware_detection": "alert",
    "prefetch": "prefetch",
    "prefetch_metadata": "prefetch",
}


FILTER_TO_GROUP = {
    "Все типы": "all",
    "Файлы": "file",
    "Процессы": "process",
    "Закрепление": "persistence",
    "Сеть": "network",
    "События": "event",
    "Оповещения": "alert",
    "Пользователи": "user",
    "Prefetch": "prefetch",
    "Источники попадания": "source",
}


GROUP_LABELS = {
    "file": "Файл",
    "process": "Процесс",
    "user": "Пользователь",
    "host": "Узел",
    "persistence": "Закрепление",
    "network": "Сеть",
    "event": "Событие",
    "alert": "Оповещение",
    "prefetch": "Prefetch",
    "source": "Источник попадания",
    "artifact": "Артефакт",
}


def entity_group(entity_type: str) -> str:
    return ENTITY_GROUPS.get(str(entity_type), "artifact")


def entity_label(entity_type: str) -> str:
    return GROUP_LABELS.get(entity_group(entity_type), str(entity_type))
