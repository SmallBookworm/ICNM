package com.icnm.service;

import com.github.pagehelper.PageHelper;
import com.github.pagehelper.PageInfo;
import com.icnm.entity.HeathMonitor;
import com.icnm.mapper.HeathMonitorMapper;
import com.icnm.util.DateUtil;
import com.icnm.util.UUIDUtil;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Map;

/**
 * @version v2.3
 * @ClassName:HeathMonitorService.java
 * @author: http://www.wgstart.com
 * @date: 2019年11月16日
 * @Description: HeathMonitorService.java
 * @Copyright: 2017-2024 icnm. All rights reserved.
 */
@Service
public class HeathMonitorService {

    public PageInfo selectByParams(Map<String, Object> params, int currPage, int pageSize) throws Exception {
        PageHelper.startPage(currPage, pageSize);
        List<HeathMonitor> list = heathMonitorMapper.selectByParams(params);
        PageInfo<HeathMonitor> pageInfo = new PageInfo<HeathMonitor>(list);
        return pageInfo;
    }

    public void save(HeathMonitor HeathMonitor) throws Exception {
        HeathMonitor.setId(UUIDUtil.getUUID());
        HeathMonitor.setCreateTime(DateUtil.getNowTime());
        if (StringUtils.isEmpty(HeathMonitor.getHeathUrl())) {
            HeathMonitor.setHeathUrl(HeathMonitor.getHeathUrl().trim());
        }
        heathMonitorMapper.save(HeathMonitor);
    }


    @Transactional
    public void saveRecord(List<HeathMonitor> recordList) throws Exception {
        if (recordList.size() < 1) {
            return;
        }
        for (HeathMonitor as : recordList) {
            as.setId(UUIDUtil.getUUID());
        }
        heathMonitorMapper.insertList(recordList);
    }

    public int countByParams(Map<String, Object> params) throws Exception {
        return heathMonitorMapper.countByParams(params);
    }

    @Transactional
    public int deleteById(String[] id) throws Exception {
        return heathMonitorMapper.deleteById(id);
    }

    public void updateById(HeathMonitor HeathMonitor)
            throws Exception {
        if (StringUtils.isEmpty(HeathMonitor.getHeathUrl())) {
            HeathMonitor.setHeathUrl(HeathMonitor.getHeathUrl().trim());
        }
        heathMonitorMapper.updateById(HeathMonitor);
    }

    public HeathMonitor selectById(String id) throws Exception {
        return heathMonitorMapper.selectById(id);
    }

    @Transactional
    public void updateRecord(List<HeathMonitor> recordList) throws Exception {
        heathMonitorMapper.updateList(recordList);
    }

    public List<HeathMonitor> selectAllByParams(Map<String, Object> params) throws Exception {
        return heathMonitorMapper.selectAllByParams(params);
    }


    @Autowired
    private HeathMonitorMapper heathMonitorMapper;


}
