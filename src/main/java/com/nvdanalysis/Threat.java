package com.nvdanalysis;

import java.util.List;

public class Threat {
    public final String pid;
    public final String name;
    public final String serviceModel;
    public final List<String> keywords;

    public Threat(String pid, String name, String serviceModel, List<String> keywords) {
        this.pid          = pid;
        this.name         = name;
        this.serviceModel = serviceModel;
        this.keywords     = keywords;
    }
}
