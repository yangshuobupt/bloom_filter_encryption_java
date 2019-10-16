package ch.krmpoti.master;

public enum HIBEParam {
    G("g"), H("h");

    private String value;

    HIBEParam(String value){
        this.value = value;
    }

    public String withIndex(int index) {
        return this.value + index;
    }
}
