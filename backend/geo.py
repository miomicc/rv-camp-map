"""
坐标系转换模块。

国内地图应用的第一个坑：手机 GPS 拿到的是 WGS-84，
而高德/腾讯/Google 中国区底图用的是 GCJ-02（火星坐标），
百度用的是再加密一层的 BD-09。

不纠偏的话，中国大陆范围内偏差可达 300~800 米。
对"标记某家营地位置"这种应用来说等于数据全废。

本模块提供三坐标系互转，精度在 10 米以内。
算法为公开的标准实现（源于 eviltransform / coordtransform 系列）。
"""

import math

__all__ = [
    "wgs84_to_gcj02", "gcj02_to_wgs84",
    "gcj02_to_bd09", "bd09_to_gcj02",
    "wgs84_to_bd09", "bd09_to_wgs84",
    "out_of_china",
]

_A = 6378245.0          # 克拉索夫斯基椭球长半轴
_EE = 0.00669342162296594323  # 偏心率平方


def out_of_china(lng: float, lat: float) -> bool:
    """判断坐标是否在中国境外。

    境外不做偏移处理——GCJ-02 加密只对中国大陆生效。
    这里用的是粗略的经纬度矩形范围（主流实现通用做法）。
    """
    if not (72.004 <= lng <= 137.8347):
        return True
    if not (0.8293 <= lat <= 55.8271):
        return True
    return False


def _transform_lat(lng: float, lat: float) -> float:
    ret = -100.0 + 2.0 * lng + 3.0 * lat + 0.2 * lat * lat + \
        0.1 * lng * lat + 0.2 * math.sqrt(abs(lng))
    ret += (20.0 * math.sin(6.0 * lng * math.pi) +
            20.0 * math.sin(2.0 * lng * math.pi)) * 2.0 / 3.0
    ret += (20.0 * math.sin(lat * math.pi) +
            40.0 * math.sin(lat / 3.0 * math.pi)) * 2.0 / 3.0
    ret += (160.0 * math.sin(lat / 12.0 * math.pi) +
            320 * math.sin(lat * math.pi / 30.0)) * 2.0 / 3.0
    return ret


def _transform_lng(lng: float, lat: float) -> float:
    ret = 300.0 + lng + 2.0 * lat + 0.1 * lng * lng + \
        0.1 * lng * lat + 0.1 * math.sqrt(abs(lng))
    ret += (20.0 * math.sin(6.0 * lng * math.pi) +
            20.0 * math.sin(2.0 * lng * math.pi)) * 2.0 / 3.0
    ret += (20.0 * math.sin(lng * math.pi) +
            40.0 * math.sin(lng / 3.0 * math.pi)) * 2.0 / 3.0
    ret += (150.0 * math.sin(lng / 12.0 * math.pi) +
            300.0 * math.sin(lng / 30.0 * math.pi)) * 2.0 / 3.0
    return ret


def wgs84_to_gcj02(lng: float, lat: float):
    """WGS-84（GPS 原始坐标）→ GCJ-02（火星坐标，国内底图）"""
    if out_of_china(lng, lat):
        return lng, lat
    dlat = _transform_lat(lng - 105.0, lat - 35.0)
    dlng = _transform_lng(lng - 105.0, lat - 35.0)
    radlat = lat / 180.0 * math.pi
    magic = math.sin(radlat)
    magic = 1 - _EE * magic * magic
    sqrtmagic = math.sqrt(magic)
    dlat = (dlat * 180.0) / ((_A * (1 - _EE)) / (magic * sqrtmagic) * math.pi)
    dlng = (dlng * 180.0) / (_A / sqrtmagic * math.cos(radlat) * math.pi)
    return lng + dlng, lat + dlat


def gcj02_to_wgs84(lng: float, lat: float):
    """GCJ-02 → WGS-84（迭代逼近，误差 < 1e-6 度）"""
    if out_of_china(lng, lat):
        return lng, lat
    # 先用一次粗略反算，再迭代收敛
    wlng, wlat = lng, lat
    for _ in range(3):
        tlng, tlat = wgs84_to_gcj02(wlng, wlat)
        wlng += lng - tlng
        wlat += lat - tlat
    return wlng, wlat


_X_PI = math.pi * 3000.0 / 180.0


def gcj02_to_bd09(lng: float, lat: float):
    """GCJ-02 → BD-09（百度坐标）"""
    z = math.sqrt(lng * lng + lat * lat) + 0.00002 * math.sin(lat * _X_PI)
    theta = math.atan2(lat, lng) + 0.000003 * math.cos(lng * _X_PI)
    return z * math.cos(theta) + 0.0065, z * math.sin(theta) + 0.006


def bd09_to_gcj02(lng: float, lat: float):
    """BD-09 → GCJ-02"""
    x = lng - 0.0065
    y = lat - 0.006
    z = math.sqrt(x * x + y * y) - 0.00002 * math.sin(y * _X_PI)
    theta = math.atan2(y, x) - 0.000003 * math.cos(x * _X_PI)
    return z * math.cos(theta), z * math.sin(theta)


def wgs84_to_bd09(lng: float, lat: float):
    return gcj02_to_bd09(*wgs84_to_gcj02(lng, lat))


def bd09_to_wgs84(lng: float, lat: float):
    return gcj02_to_wgs84(*bd09_to_gcj02(lng, lat))


def haversine_m(lng1: float, lat1: float, lng2: float, lat2: float) -> float:
    """两点球面距离（米）。用于"附近营地"和去重。"""
    r = 6371008.8
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp = math.radians(lat2 - lat1)
    dl = math.radians(lng2 - lng1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * r * math.asin(math.sqrt(a))


if __name__ == "__main__":
    # 自检：天安门 WGS-84 参考点
    w = (116.3912757, 39.9074740)
    g = wgs84_to_gcj02(*w)
    b = wgs84_to_bd09(*w)
    back_w = gcj02_to_wgs84(*g)
    print(f"WGS84 输入      : {w[0]:.7f}, {w[1]:.7f}")
    print(f"→ GCJ-02        : {g[0]:.7f}, {g[1]:.7f}")
    print(f"→ BD-09         : {b[0]:.7f}, {b[1]:.7f}")
    print(f"GCJ-02 → WGS84  : {back_w[0]:.7f}, {back_w[1]:.7f}")
    print(f"往返误差        : {haversine_m(w[0], w[1], back_w[0], back_w[1]):.4f} 米")
    print(f"火星偏移量      : {haversine_m(w[0], w[1], g[0], g[1]):.1f} 米")
